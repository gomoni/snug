package rules

// The word sets the rules compare against. Each is the words that signal one
// thing; a request is read by which sets its clauses touch. They were written
// from the user messages of setup/model/data/train-v4.jsonl and from the words
// snug-setup itself tells the human to say. The gold sets were not used to
// write them.
var (
	netWords     = set("internet internetu internetzugang network networking net online netzwerk síť sítě site download downloads downloading stahování stahovat fetch crates pypi registry egress")
	netTools     = set("npm pip pip3 cargo yarn pnpm uv gem bundle maven gradle composer")
	offWords     = set("offline off-line airgapped air-gapped airgap disconnect disconnected unplug")
	negWords     = set("nepotřebuju no not don't dont never without disable disabled off none nicht kein keine keinen ohne ne bez nechci isn't doesn't shouldn't can't cannot")
	dropWords    = set("remove drop forget delete unmount revoke odeber odstraň smaž entfernen")
	desktopWords = set("x11 wayland gui clipboard dbus d-bus pulseaudio pulse xorg display desktop notifications screenshot screenshots")
	podmanWords  = set("docker podman container containers testcontainers compose docker-compose daemon kontejner kontejnery")
	imageWords   = set("image images dockerfile containerfile buildah")
	buildWords   = set("build builds building bauen sestavit")
	writeWords   = set("read/write rewrite write writable writeable edit modify change rw read-write zapisovat zápis schreiben schreib touch touching")
	readWords    = set("read readable ro look see view peek browse lesend lesen číst přečti přečíst podívej mount inspect")
	onlyRead     = set("read-only readonly lesend ro")
	tmpWords     = set("tmpfs scratch temporary temp ephemeral memory throwaway discarded survive")
	hereWords    = set("here project repo repository code sem tady hier projekt projektu target")
	parentWords  = set("parent sibling siblings neighbouring neighboring")
	claudeWords  = set("claude anthropic")
	pushWords    = set("push pushes pushing pushovat pushnout")
	signWords    = set("sign signs signed signing signature signatures signiert podepisovat podepsat")
	keyWords     = set("key keys klíč klíče schlüssel")
	accountWords = set("account accounts login logins účet")
	listWords    = set("list which what what's whats show loaded configured available welche geladen")
	bothWords    = set("both two multiple second another too beide oba obě")
	inheritWords = set("keep pass inherit export copy forward propagate through")
	nameVerbs    = set("call name pojmenuj nenne benenne")
	showWords    = set("show print display dump ukaž zeig")
	saveWords    = set("save persist uložit ulož speichern fertig")
	helpWords    = set("help hi hello hey thanks thank options díky ahoj hallo danke")
	includeVerbs = set("include reuse")
	doorWords    = set("door serve expose listen")
	denyWords    = set("hide exclude block deny blacklist invisible mask")
	modifiers    = set("configure configured accordingly decide allow permissions grant things only away thrown afterwards memory fine here email name author identity address config configuration profile setup tell figure out what whats")
	recommend    = set("recommend recommends recommended recommending suggest suggests suggested suggesting suggestion advise advice doporuč doporučit empfehlen")
	analyzeWords = set("analyze analyse analysis scan")
	undoWords    = set("undo revert rückgängig")
	stageWords   = set("stage available binary binaries executable tools tool")
	langWords    = set("go golang node nodejs javascript typescript npm python pip rust cargo")
	questionHead = set("what which how does do is are can could will would should why where who when welche was wie kann ist jak co který která je")
	identityNoun = set("identity identities account accounts ssh key keys signing login logins author")
	seccompWords = set("seccomp")
	sensitiveDir = set(".ssh .aws .gnupg .netrc .docker .kube .git-credentials .npmrc .pypirc")
	offTopic     = set("joke poem song story weather recipe tuple rain forecast")
)

// fillers are words that carry no request by themselves. A clause made only
// of these and of words the rules already used changes nothing and is not an
// unknown.
var fillers = set(`a an the it its it's this that these those there here's is are be been was were
	i i'd i'm i've me my mine we our you your he she they them
	to of in on at for from with by as into onto about so if or nor
	please pls plz thanks thank ok okay right yes sure well hmm hm actually just also too
	let make give get have has had need needs needed want wants should must can could would will shall
	do does did done set up already after all some any every everything nothing thing things
	safe secure properly working work works fine good nice now again still really
	sandbox inside access able allowed going like way
	bitte danke prosím díky potřebuju potřebuje aby mohl mohla musí chci brauche muss soll ich es`)

// notTypos are real words within a correction's reach of a lexicon word that
// must stay as they are: "same" is not "save", "calls" is not "call".
var notTypos = set(`same name names named game came come some home hope those these them then than
	user users used uses last list mode code made node well tell bind find kind mind sees seed
	calls call called scan can sort port part ports parts real deal reads ready head rest test tests
	need feed seen been mine line fine file files sure pure more move love live give gave
	where there when what that than wait want gone done none note notes nets bits
	look took book cook keep kept deep peek peak view vies shows snow slow know known
	editor editors visual pager term anything many branches codeberg full mein sein meine nepotřebuju
	reachable remote kill trust server servers side toml venv that's borg helm hood hook docs directly
	pyproject world plus roll toho jako jaké mail rights hand`)

// meaningful are the words that ask for something: every set above but the
// fillers and the modifiers. A part of a request holding none of them is
// narration ("the agent runs a server") and is not reported as unknown when
// the rest was understood.
var meaningful = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range []map[string]bool{netWords, netTools, desktopWords, podmanWords, imageWords, buildWords, writeWords,
		readWords, onlyRead, tmpWords, parentWords, claudeWords, pushWords, signWords, keyWords, accountWords, listWords,
		inheritWords, nameVerbs, showWords, saveWords, includeVerbs, doorWords, denyWords, recommend, analyzeWords, undoWords,
		stageWords, langWords, seccompWords, offTopic} {
		for w := range s {
			if !fillers[w] && !modifiers[w] {
				m[w] = true
			}
		}
	}
	return m
}()

// lexicon is every word a correction may land on: the words of the sets
// above and the fillers.
var lexicon = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range []map[string]bool{netWords, netTools, offWords, negWords, dropWords, desktopWords, podmanWords,
		imageWords, buildWords, writeWords, readWords, onlyRead, tmpWords, hereWords, parentWords, claudeWords, pushWords,
		signWords, keyWords, accountWords, listWords, bothWords, inheritWords, nameVerbs, showWords, saveWords, helpWords,
		includeVerbs, doorWords, denyWords, recommend, analyzeWords, undoWords, stageWords, langWords, questionHead,
		identityNoun, seccompWords, offTopic, fillers, modifiers, extraWords} {
		for w := range s {
			m[w] = true
		}
	}
	return m
}()

// extraWords are lexicon words that only appear inside a phrase the rules
// look for ("pull images", "host network").
var extraWords = set(`github gh git commit commits commited author email profile profiles config readme
	localhost host local postgres redis mysql mongo database laptop machine browser publish
	directory folder dir whole entire environment variable env path secret secrets token password
	credentials repos private clone default defaults pull shell value already instructions ignore previous
	disregard prompt next above apis api check through figure open openai readme take back put leave socket sock namespace hidden run state current`)
