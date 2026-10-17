// Command snug-setup suggests a snug profile for a project directory, shows it
// one row per part, and writes it once you agree. It reads the project and the
// host, never runs the project's code, and never writes a file without showing
// a diff and getting a y.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/probe"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/suggest"
	"github.com/gomoni/snug/setup/internal/tui"
	"github.com/gomoni/snug/setup/internal/verify"
	"github.com/gomoni/snug/setup/internal/write"
)

const usage = `usage: snug-setup [--print] [--profile-dir DIR] [--name NAME] [DIR]

  Suggests a snug profile for DIR (default: the current directory) on one screen,
  a row per part, each with a reason. Change any row, press w to see the diff and
  y to write the profile, then run the command it prints.

  --print              print the suggestion as TOML on stdout and the warnings on stderr; no
                       screen, no prompt, nothing written. Unsure picks come out as commented
                       include lines. An ambiguous identity (two profiles of yours match the
                       project equally) is left out, says so on stderr, and still exits 0.
  --profile-dir DIR    where the profile is written (default: $XDG_CONFIG_HOME/snug/profiles.d)
  --name NAME          the profile's name instead of the one suggested; with --print, the way
                       past a name that exists already
  DIR                  the project directory

exit status:
  0    written, printed, or quit with nothing written
  1    usage or startup error
  130  interrupted
`

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug-setup: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

type options struct {
	print                 bool
	profileDir, name, dir string
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("snug-setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var o options
	fs.BoolVar(&o.print, "print", false, "")
	fs.StringVar(&o.profileDir, "profile-dir", "", "")
	fs.StringVar(&o.name, "name", "", "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 1 {
		return o, errors.New("at most one directory")
	}
	o.dir = "."
	if fs.NArg() == 1 {
		o.dir = fs.Arg(0)
	}
	return o, nil
}

func run() (int, error) {
	o, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usage)
			return 0, nil
		}
		fmt.Fprint(os.Stderr, usage)
		return 1, err
	}
	if o.name != "" && !draft.ValidProfileName(o.name) {
		return 1, fmt.Errorf("--name %q is not a profile name (letters, digits and dashes; no underscore, dot or leading @)", o.name)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return 1, fmt.Errorf("cannot find your home directory: %w (set HOME)", err)
	}
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	target, err := filepath.Abs(o.dir)
	if err != nil {
		return 1, err
	}
	if t, err := filepath.EvalSymlinks(target); err == nil {
		target = t
	}
	if err := draft.CheckTarget(target); err != nil {
		return 1, err
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		return 1, fmt.Errorf("%s is not a directory", target)
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	defaultDir := filepath.Join(cfg, "snug", "profiles.d")
	if o.profileDir == "" {
		o.profileDir = defaultDir
	}
	tty := isTerminal(os.Stdin) && isTerminal(os.Stdout)
	if !o.print && !tty {
		return 1, errors.New("stdin is not a terminal; use --print to get the suggestion as TOML")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := &setup{
		o: o, home: home, target: target, tty: tty, ctx: ctx,
		run: hostfacts.ExecRunner, lookPath: exec.LookPath, defaultDir: defaultDir,
	}
	s.snug, _ = s.lookPath("snug")
	s.gather()
	if o.print {
		return s.printOnly()
	}
	return s.interactive()
}

type setup struct {
	o      options
	home   string
	target string
	tty    bool
	ctx    context.Context
	run    hostfacts.Runner
	// lookPath finds a command on PATH; tests replace it.
	lookPath func(string) (string, error)
	snug     string
	facts    ingest.Facts
	sel      suggest.Selection
	// defaultDir is where snug reads profiles from when nobody points it
	// elsewhere.
	defaultDir string
}

func (s *setup) gather() {
	dirs := ingest.ProfileDirs(os.Getenv("XDG_CONFIG_HOME"), s.home)
	s.facts = ingest.Gather(s.ctx, s.target, s.home, dirs, s.run)
	s.facts.Binaries = ingest.LocateBinaries(suggest.ToolBinaries(), s.lookPath, filepath.EvalSymlinks)
	s.sel = suggest.Suggest(s.facts, s.home, s.target)
	if s.o.name != "" {
		s.sel.Text[suggest.Name] = s.o.name
	}
}

func (s *setup) host() draft.Host {
	return draft.Host{Home: s.home, Target: s.target, RuntimeDir: os.Getenv("XDG_RUNTIME_DIR"), ConfigHome: os.Getenv("XDG_CONFIG_HOME")}
}

func (s *setup) build(sel suggest.Selection) (*draft.Draft, map[suggest.RowID]string) {
	return suggest.Build(sel, s.host(), s.facts.Profiles)
}

func (s *setup) notes() []string {
	var out []string
	out = append(out, s.facts.Warnings...)
	out = append(out, s.facts.Target.Warnings...)
	return out
}

func (s *setup) printOnly() (int, error) {
	if s.snug == "" {
		fmt.Fprintln(os.Stderr, "! snug not on PATH: profiles not checked")
	}
	name := s.sel.Text[suggest.Name]
	if s.o.name == "" {
		if i := slices.IndexFunc(s.facts.Profiles, func(p ingest.Profile) bool { return p.Name == name }); i >= 0 {
			return 1, fmt.Errorf("profile name %s exists in %s; pass --name", name, safe.Inline(filepath.Join(s.facts.Profiles[i].Dir, s.facts.Profiles[i].File)))
		}
	}
	d, refused := s.build(s.sel)
	for _, w := range probe.Check(s.ctx, s.run, s.snug, s.target, probe.Scope(s.facts.Profiles, d)) {
		fmt.Fprintf(os.Stderr, "! %s: %s\n", safe.Inline(filepath.Base(w.File)), w.Line)
	}
	for _, n := range s.notes() {
		fmt.Fprintf(os.Stderr, "! %s\n", safe.Inline(n))
	}
	if r := s.sel.Rows[suggest.Identity]; s.sel.Pick[suggest.Identity] == 0 && strings.HasSuffix(r.Choices[0].Why, "— pick one") {
		fmt.Fprintf(os.Stderr, "identity: %s\n", r.Choices[0].Why)
	}
	if w := s.sel.IdentityWarning(s.sel.Pick[suggest.Identity]); w != "" {
		fmt.Fprintf(os.Stderr, "! %s\n", w)
	}
	for id, msg := range refused {
		fmt.Fprintf(os.Stderr, "! %s: not in the profile: %s\n", strings.ToLower(rowName(id)), safe.Inline(msg))
	}
	out := d.Render()
	if id, _ := suggest.BuildIdentity(s.sel, s.host()); id != nil {
		out = id.Render() + "\n" + out
	}
	for _, r := range s.sel.Rows {
		if !r.Sure && s.sel.Pick[r.ID] == r.Suggested {
			out += fmt.Sprintf("# include = [%q]  # %s\n", r.Choices[r.Cand].Label, s.sel.Current(r.ID).Why)
		}
	}
	fmt.Print(out)
	return 0, nil
}

func rowName(id suggest.RowID) string {
	return [...]string{"NAME", "DESC", "BASE", "IDENTITY", "AGENT", "NETWORK", "CONTAINERS", "TOOLS", "ENV"}[id]
}

func (s *setup) short(p string) string {
	if s.home != "" && (p == s.home || strings.HasPrefix(p, s.home+"/")) {
		return "~" + strings.TrimPrefix(p, s.home)
	}
	return p
}

func (s *setup) interactive() (int, error) {
	status := ""
	for {
		if s.snug != "" {
			fmt.Fprintln(os.Stderr, "checking your profiles…")
		}
		d, _ := s.build(s.sel)
		warns := probe.Check(s.ctx, s.run, s.snug, s.target, probe.Scope(s.facts.Profiles, d))
		var wrote *write.Plan
		var wroteDraft *draft.Draft
		cfg := tui.Config{
			Target:      s.short(s.target),
			Sel:         s.sel,
			Warnings:    warns,
			Notes:       s.notes(),
			SnugMissing: s.snug == "",
			NoColor:     os.Getenv("NO_COLOR") != "",
			Build:       s.build,
			Status:      status,
			Plan: func(sel suggest.Selection) (tui.Review, error) {
				return s.reviewWrite(sel, warns, func(p write.Plan, d *draft.Draft) { wrote, wroteDraft = &p, d })
			},
			PlanFix: s.reviewFix,
		}
		if s.snug != "" {
			cfg.DryRun = func(sel suggest.Selection) (string, error) {
				d, _ := s.build(sel)
				id, _ := suggest.BuildIdentity(sel, s.host())
				return write.DryRunText(s.ctx, s.run, s.snug, d, s.verifyFiles(d, id))
			}
		}
		final, err := tea.NewProgram(tui.New(cfg), tea.WithContext(s.ctx)).Run()
		if s.ctx.Err() != nil {
			return 130, nil
		}
		if err != nil {
			return 1, fmt.Errorf("the screen failed: %w (use --print where there is no usable terminal)", err)
		}
		out := final.(tui.Model).Outcome()
		s.sel = out.Sel
		switch out.Result {
		case tui.Quit:
			return 0, nil
		case tui.Interrupted:
			return 130, nil
		case tui.Fixed:
			status = out.Done
			s.gather2()
		case tui.Write, tui.Edit:
			fmt.Println(out.Done)
			if out.Result == tui.Edit {
				return s.edit(wrote.Path, wroteDraft, out.Row), nil
			}
			s.printRun(wroteDraft)
			return 0, nil
		}
	}
}

// printRun prints how to run the profile just written, or why that line would
// not find it.
func (s *setup) printRun(d *draft.Draft) {
	for _, l := range write.AfterWrite(write.RunLine(d, mustGetwd()), s.o.profileDir, s.defaultDir) {
		fmt.Println(l)
	}
}

// gather2 re-reads the facts after a fix changed a profile file, keeping the
// person's selection.
func (s *setup) gather2() {
	keep := s.sel
	s.gather()
	s.sel = keep
}

// verifyFiles returns the profile files snug needs beside d to resolve it:
// the person's own for every profile d includes besides the built-ins, and
// the new identity profile id, which no file holds yet. id is nil when the
// identity is not a new one.
func (s *setup) verifyFiles(d, id *draft.Draft) []verify.File {
	var names []string
	for _, n := range d.Include {
		if !strings.HasPrefix(n, "@") && (id == nil || n != id.Name) {
			names = append(names, n)
		}
	}
	out := write.IdentityFiles(s.facts.Files, s.facts.Profiles, d.Name, names...)
	if id != nil {
		out = append(out, verify.File{Name: id.Name + ".toml", Body: []byte(id.Render())})
	}
	return out
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(wd); err == nil {
		return r
	}
	return wd
}

// reviewWrite prepares writing sel for the confirmation screen. Everything
// that cannot be written is Blocked and shown; an error is for what cannot be
// answered at all. wrote is called with the plan and draft once Apply has
// written the file. A new identity profile is written first and shown with the
// project's on the same screen: the project includes it.
func (s *setup) reviewWrite(sel suggest.Selection, warns []probe.Warning, wrote func(write.Plan, *draft.Draft)) (tui.Review, error) {
	d, refused := s.build(sel)
	id, _ := suggest.BuildIdentity(sel, s.host())
	name := sel.IdentityProfile()
	var idWarn *probe.Warning
	for i := range warns {
		if name != "" && slices.Contains(warns[i].Profiles, name) {
			idWarn = &warns[i]
		}
	}
	p, err := write.Prepare(s.ctx, d, s.o.profileDir, s.snug, s.run, s.facts.Profiles, s.verifyFiles(d, id), idWarn)
	if err != nil {
		return tui.Review{}, err
	}
	for r, msg := range refused {
		p.Blocked = append(p.Blocked, fmt.Sprintf("%s is on the screen but not in the profile: %s", strings.ToLower(rowName(r)), safe.Inline(msg)))
	}
	plans := []write.Plan{p}
	done := "wrote " + safe.Inline(p.Path)
	var idPlan *write.Plan
	if id != nil {
		ip, err := write.PrepareIdentity(id, s.o.profileDir, s.facts.Profiles)
		if err != nil {
			return tui.Review{}, err
		}
		if id.Name == d.Name {
			p.Blocked = append(p.Blocked, fmt.Sprintf("NAME %s is also the name of the new identity profile; change NAME", safe.Inline(d.Name)))
		}
		idPlan = &ip
		plans = []write.Plan{ip, p}
		done = "wrote " + safe.Inline(ip.Path) + " and " + safe.Inline(p.Path)
	}
	title, body, blocked := write.Together(plans...)
	return tui.Review{
		Title:   title,
		Body:    body,
		Blocked: blocked,
		Done:    done,
		Apply: func() error {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			if idPlan != nil {
				if err := write.Apply(*idPlan); err != nil {
					return err
				}
			}
			if err := write.Apply(p); err != nil {
				if idPlan != nil {
					return fmt.Errorf("wrote %s but not %s: %w", safe.Inline(idPlan.Path), safe.Inline(p.Path), err)
				}
				return err
			}
			wrote(p, d)
			return nil
		},
	}, nil
}

func (s *setup) reviewFix(w probe.Warning) (tui.Review, error) {
	path, backup, oldB, newB, err := write.PrepareFix(w, time.Now())
	if err != nil {
		return tui.Review{}, err
	}
	return tui.Review{
		Title: fmt.Sprintf("fixes %s (original saved as %s)", safe.Inline(path), safe.Inline(backup)),
		Body:  write.LineDiff(string(oldB), string(newB)),
		Done:  "fixed " + safe.Inline(path),
		Apply: func() error {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			return write.ApplyFix(path, backup, oldB, newB)
		},
	}, nil
}

// edit opens path in $EDITOR (fallback vi) at the row's line, then asks snug
// once about the result and prints the run line.
func (s *setup) edit(path string, d *draft.Draft, row suggest.RowID) int {
	argv := strings.Fields(os.Getenv("EDITOR"))
	if len(argv) == 0 {
		argv = []string{"vi"}
	}
	switch filepath.Base(argv[0]) {
	case "vi", "vim", "nvim", "nano":
		if n := write.LineOf(d.Render(), s.rowToken(row)); n > 0 {
			argv = append(argv, fmt.Sprintf("+%d", n))
		}
	}
	cmd := exec.Command(argv[0], append(argv[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "snug-setup: the editor %q failed: %v (the profile is written at %s)\n", argv[0], err, path)
		return 1
	}
	if s.snug != "" {
		res, err := s.run(s.ctx, nil, s.snug, "--dry-run", "-p", d.Name, s.target)
		if err == nil {
			fmt.Println("snug: ok")
		} else {
			msg := strings.TrimSpace(string(res.Stderr) + string(res.Stdout))
			first, _, _ := strings.Cut(msg, "\n")
			fmt.Printf("snug: %s\n", safe.Inline(first))
		}
	}
	fmt.Println(write.RunLine(d, mustGetwd()))
	return 0
}

// rowToken is the text the row's grant is rendered with, for the editor to
// open the file at.
func (s *setup) rowToken(row suggest.RowID) string {
	label := s.sel.Rows[row].Choices[s.sel.Pick[row]].Label
	switch row {
	case suggest.Desc:
		return "description"
	case suggest.Identity:
		if l := s.sel.IdentityProfile(); l != "" {
			return `"` + l + `"`
		}
		return `"@git"`
	case suggest.Env:
		if f := strings.Fields(label); len(f) > 0 && label != suggest.Off {
			return f[0]
		}
	case suggest.Base, suggest.Agent, suggest.Network, suggest.Containers:
		for _, f := range strings.Fields(label) {
			if strings.HasPrefix(f, "@") && f != "@sys" && f != "@home" && f != "@target-rw" {
				return `"` + f + `"`
			}
		}
		if !s.sel.Rows[row].Sure {
			return `"` + s.sel.Rows[row].Choices[s.sel.Rows[row].Cand].Label + `"`
		}
	}
	return "[profile."
}
