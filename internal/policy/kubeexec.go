package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gomoni/snug/internal/kubecfg"
)

// KubePlugin is the host context's exec plugin as snug will run it: the row of
// the fixed grammar it matched and the argv snug BUILT from the fields it
// parsed — never the file's own slice. internal/cli resolves Command and runs
// it; nothing here touches the host.
type KubePlugin struct {
	// Row is the grammar row: kubelogin, aws or aws-iam-authenticator.
	Row string
	// Command is the file's command, bare or absolute. A bare name is looked
	// up on KubePluginPATH only.
	Command string
	// Args is the built argv after the command.
	Args []string
	// APIVersion is the ExecCredential version the file names; the plugin's
	// output must carry the same one.
	APIVersion string
	// AWSProfile is identity.kube.aws_profile, for an aws row; "" otherwise.
	AWSProfile string
	// ConfigDirs are the host directories the plugin reads its own
	// configuration and cache from, under the host home. A grant that makes
	// one writable refuses the run: a payload writing ~/.aws/config chooses a
	// credential_process the host runs.
	ConfigDirs []string
	// Helpers are other programs the plugin itself runs off KubePluginPATH
	// (kubelogin --login azurecli runs az). They are judged for writability.
	Helpers []string
	// Reach says what the plugin's token is valid for beyond the pinned
	// server, for the screen: the proxy sends it nowhere else, but a token's
	// own scope is the cluster's and the cloud's, not snug's.
	Reach string
}

// KubePluginPATH is the PATH a plugin runs with and the only directories a
// bare command is looked up in — never snug's inherited PATH, and never the
// file's exec.env. /usr/local/bin is on it because that is where kubelogin
// and the aws v2 installer put their binaries.
const KubePluginPATH = "/usr/local/bin:/usr/bin:/bin"

// KubePluginEnv is a plugin's whole environment: PATH, HOME — the host home,
// because these are the host's own tools reading the host's own ~/.azure and
// ~/.aws — PYTHONNOUSERSITE=1, and AWS_PROFILE for an aws row with
// identity.kube.aws_profile set. Nothing is inherited: KUBECONFIG, a proxy
// variable, AWS_* or AZURE_* in snug's environment would steer what the
// plugin authenticates as.
//
// PYTHONNOUSERSITE because az, which kubelogin runs, is a Python program
// started without -s: it loads ~/.local/lib/python3.*/site-packages/*.pth
// from the host home, and a grant that makes that directory writable would
// let a payload plant code the host runs (red team, measured on the
// azure-cli package's /usr/bin/az; with the variable set it did not load).
func (k *KubePlugin) KubePluginEnv(home string) []string {
	env := []string{"PATH=" + KubePluginPATH, "HOME=" + home, "PYTHONNOUSERSITE=1"}
	if k.AWSProfile != "" {
		env = append(env, "AWS_PROFILE="+k.AWSProfile)
	}
	return env
}

// EnvNames is the names KubePluginEnv sets, for the screen.
func (k *KubePlugin) EnvNames() []string {
	n := []string{"PATH", "HOME", "PYTHONNOUSERSITE"}
	if k.AWSProfile != "" {
		n = append(n, "AWS_PROFILE")
	}
	return n
}

var (
	uuidShape       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	azureEnvShape   = regexp.MustCompile(`^[A-Za-z]{1,40}$`)
	awsRegionShape  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	eksClusterShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)
	awsRoleShape    = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	awsProfileShape = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// kubePluginRows names the accepted plugins for a refusal.
const kubePluginRows = "kubelogin (--login azurecli), aws eks get-token, aws-iam-authenticator token"

// kubeArgs reads a plugin's args as a subcommand path followed by flags, each
// flag at most once and only from allowed, every value checked against its
// shape. Both `--flag value` and `--flag=value` are read. A positional where
// a flag was expected, an unknown flag, a repeated flag or a value of the
// wrong shape refuses: a basename allowlist bounds nothing, because the
// plugin is code and its argv is what it does.
func kubeArgs(row string, args, subcommands []string, allowed map[string]*regexp.Regexp, aliases map[string]string) (map[string]string, error) {
	i := 0
	for _, sub := range subcommands {
		if i >= len(args) || args[i] != sub {
			return nil, fmt.Errorf("%s args must start with %s", row, strings.Join(subcommands, " "))
		}
		i++
	}
	got := map[string]string{}
	for ; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("%s args: %s is not a flag, and no positional argument is accepted there",
				row, kq(a))
		}
		name, val, inline := strings.Cut(a, "=")
		if canon, ok := aliases[name]; ok {
			name = canon
		}
		shape, ok := allowed[name]
		if !ok {
			return nil, fmt.Errorf("%s args: flag %s is outside the grammar snug runs this plugin with", row, kq(name))
		}
		if _, dup := got[name]; dup {
			return nil, fmt.Errorf("%s args: flag %s appears twice", row, kq(name))
		}
		if !inline {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s args: flag %s has no value", row, kq(name))
			}
			i++
			val = args[i]
		}
		if !shape.MatchString(val) {
			return nil, fmt.Errorf("%s args: %s %s is not the shape snug accepts there", row, kq(name), kq(val))
		}
		got[name] = val
	}
	return got, nil
}

var anyValue = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)

// kubePluginOf matches an exec entry against the fixed grammar and builds the
// argv snug will run. k is the profile's kube block (aws_profile); context
// names the context for messages.
func kubePluginOf(e *kubecfg.Exec, k IdentityKube, context string) (*KubePlugin, error) {
	ctx := kq(context)
	if e.Problem != "" {
		return nil, fmt.Errorf("the exec entry of context %s: %s", ctx, e.Problem)
	}
	if len(e.Other) > 0 {
		return nil, fmt.Errorf("the exec entry of context %s sets %s, which snug does not know; an "+
			"unrecognised field is refused rather than dropped", ctx, kq(e.Other[0]))
	}
	switch e.APIVersion {
	case "client.authentication.k8s.io/v1", "client.authentication.k8s.io/v1beta1":
	default:
		return nil, fmt.Errorf("the exec entry of context %s names apiVersion %s; snug reads "+
			"client.authentication.k8s.io/v1 and v1beta1", ctx, kq(e.APIVersion))
	}
	if e.InteractiveMode == "Always" {
		return nil, fmt.Errorf("the exec entry of context %s sets interactiveMode: Always; snug runs the "+
			"plugin on the host with no terminal, so nothing could answer it", ctx)
	}
	if e.Command == "" || strings.ContainsAny(e.Command, "\x00\n") {
		return nil, fmt.Errorf("the exec entry of context %s has no command", ctx)
	}
	if !filepath.IsAbs(e.Command) && strings.Contains(e.Command, "/") {
		return nil, fmt.Errorf("the exec entry of context %s names command %s, a relative path; name the "+
			"plugin bare (looked up on %s only) or by absolute path", ctx, kq(e.Command), KubePluginPATH)
	}
	awsProfileEnv := false
	for _, n := range e.EnvNames {
		if n == "AWS_PROFILE" {
			awsProfileEnv = true
			continue
		}
		return nil, fmt.Errorf("the exec entry of context %s sets %s in its env; snug never uses the "+
			"file's exec.env — the plugin's environment is snug's own, named on the --dry-run screen",
			ctx, kq(n))
	}

	p := &KubePlugin{Command: e.Command, APIVersion: e.APIVersion}
	switch base := filepath.Base(e.Command); base {
	case "kubelogin":
		got, err := kubeArgs("kubelogin", e.Args, []string{"get-token"}, map[string]*regexp.Regexp{
			"--login": anyValue, "--server-id": uuidShape, "--tenant-id": uuidShape,
			"--client-id": uuidShape, "--environment": azureEnvShape,
		}, map[string]string{"-l": "--login", "-t": "--tenant-id"})
		if err != nil {
			return nil, err
		}
		if got["--login"] != "azurecli" {
			mode := got["--login"]
			if mode == "" {
				mode = "devicecode (the default)"
			}
			return nil, fmt.Errorf("context %s runs kubelogin with --login %s; snug runs kubelogin only "+
				"with --login azurecli, which reads your az login on the host and holds no secret of its "+
				"own. Fix: kubelogin convert-kubeconfig -l azurecli --context %s (then az login)",
				ctx, VisibleText(mode), VisibleText(context))
		}
		if got["--server-id"] == "" {
			return nil, fmt.Errorf("context %s runs kubelogin without --server-id", ctx)
		}
		p.Row = "kubelogin"
		p.Args = []string{"get-token", "--login", "azurecli", "--server-id", got["--server-id"]}
		if t := got["--tenant-id"]; t != "" {
			p.Args = append(p.Args, "--tenant-id", t)
		}
		if env := got["--environment"]; env != "" {
			p.Args = append(p.Args, "--environment", env)
		}
		p.ConfigDirs = []string{".azure", ".kube/cache"}
		p.Helpers = []string{"az"}
		p.Reach = "an Entra token for the AKS server audience " + got["--server-id"] + ": valid as you at " +
			"EVERY AKS cluster in your tenant where you hold RBAC, for its lifetime (60-90 min per Entra " +
			"documentation, not measured)"
	case "aws":
		got, err := kubeArgs("aws", stripAWSGlobals(e.Args), []string{"eks", "get-token"}, map[string]*regexp.Regexp{
			"--cluster-name": eksClusterShape, "--region": awsRegionShape, "--role-arn": awsRoleShape,
			"--output": regexp.MustCompile(`^json$`),
		}, nil)
		if err != nil {
			return nil, err
		}
		region, err := awsGlobalRegion(e.Args, got["--region"])
		if err != nil {
			return nil, err
		}
		if got["--cluster-name"] == "" {
			return nil, fmt.Errorf("context %s runs aws eks get-token without --cluster-name", ctx)
		}
		p.Row = "aws"
		p.Args = []string{"eks", "get-token", "--cluster-name", got["--cluster-name"]}
		if region != "" {
			p.Args = append(p.Args, "--region", region)
		}
		if r := got["--role-arn"]; r != "" {
			p.Args = append(p.Args, "--role-arn", r)
		}
		p.Args = append(p.Args, "--output", "json")
		p.ConfigDirs = []string{".aws"}
		p.Reach = "a presigned STS token for EKS cluster " + got["--cluster-name"] + ", about 15 min (per " +
			"AWS documentation, not measured)"
	case "aws-iam-authenticator":
		got, err := kubeArgs("aws-iam-authenticator", e.Args, []string{"token"}, map[string]*regexp.Regexp{
			"--cluster-id": eksClusterShape, "--role": awsRoleShape, "--region": awsRegionShape,
		}, map[string]string{"-i": "--cluster-id", "-r": "--role"})
		if err != nil {
			return nil, err
		}
		if got["--cluster-id"] == "" {
			return nil, fmt.Errorf("context %s runs aws-iam-authenticator without -i/--cluster-id", ctx)
		}
		p.Row = "aws-iam-authenticator"
		p.Args = []string{"token", "--cluster-id", got["--cluster-id"]}
		if r := got["--role"]; r != "" {
			p.Args = append(p.Args, "--role", r)
		}
		if r := got["--region"]; r != "" {
			p.Args = append(p.Args, "--region", r)
		}
		p.ConfigDirs = []string{".aws"}
		p.Reach = "a presigned STS token for EKS cluster " + got["--cluster-id"] + ", about 15 min (per " +
			"AWS documentation, not measured)"
	case "gke-gcloud-auth-plugin":
		return nil, fmt.Errorf("context %s authenticates with gke-gcloud-auth-plugin, which snug does not run: "+
			"its token is cloud-platform scoped and can mint durable service-account keys. Use "+
			"token = \"serviceaccount\" with a ServiceAccount you create", ctx)
	default:
		return nil, fmt.Errorf("context %s authenticates with exec plugin %s, which snug does not run; it "+
			"runs %s", ctx, kq(base), kubePluginRows)
	}

	usesProfile := p.Row == "aws" || p.Row == "aws-iam-authenticator"
	switch {
	case k.AWSProfile != "" && !usesProfile:
		return nil, fmt.Errorf("identity.kube.aws_profile is set, but context %s runs %s, which reads no "+
			"AWS profile; drop the key", ctx, p.Row)
	case k.AWSProfile != "" && !awsProfileShape.MatchString(k.AWSProfile):
		return nil, fmt.Errorf("identity.kube.aws_profile %s is not an AWS profile name", kq(k.AWSProfile))
	case awsProfileEnv && k.AWSProfile == "":
		return nil, fmt.Errorf("the exec entry of context %s sets AWS_PROFILE in its env, and snug never "+
			"uses the file's exec.env. Name the profile in yours: identity.kube.aws_profile = \"<name>\"", ctx)
	}
	p.AWSProfile = k.AWSProfile
	return p, nil
}

// stripAWSGlobals removes `--region R` written before the subcommand, which
// is where `aws eks update-kubeconfig` puts it; awsGlobalRegion reads it.
func stripAWSGlobals(args []string) []string {
	if len(args) >= 2 && args[0] == "--region" {
		return args[2:]
	}
	return args
}

func awsGlobalRegion(args []string, local string) (string, error) {
	if len(args) >= 2 && args[0] == "--region" {
		if local != "" {
			return "", fmt.Errorf("aws args: --region appears twice")
		}
		if !awsRegionShape.MatchString(args[1]) {
			return "", fmt.Errorf("aws args: --region %s is not the shape snug accepts there", kq(args[1]))
		}
		return args[1], nil
	}
	return local, nil
}

// KubeExecArgv is the plugin's whole argv with command resolved to the binary
// internal/cli judged.
func (k *KubePlugin) KubeExecArgv(command string) []string {
	return append([]string{command}, k.Args...)
}
