package agenthook

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// This file turns the single shell command string that coding agents pass to
// their Bash tool into a list of simple commands (argv arrays) that a policy
// can reason about. The parser is deliberately conservative: it understands
// quoting, command lists (&&, ||, ;, |, &, newlines), a few transparent
// wrappers (env, command, exec, nohup, time, nice, bash -c and friends), git's
// harmless global options, and harmless redirections (descriptor duplication
// and /dev/null). Everything else that could change what actually runs
// (variable or command substitution, heredocs, redirection to files,
// subshells, environment assignments, sudo, eval, xargs, shell builtins that
// mutate state, git options that execute configured commands) is reported as
// unsupported and never silently dropped, so the caller can fail closed.
//
// Working directories are tracked as a set of possibilities: a real shell
// keeps going after a failed `cd` when the separator is `;`, `||`, `|`, or
// `&`, so a later relative path may resolve against either directory. Only a
// `cd` followed by `&&` is known to have succeeded for the next command.

// SimpleCommand is one command in a command list after normalization.
type SimpleCommand struct {
	// Argv is the normalized argument vector. Argv[0] is the command's base
	// name (directories stripped) so policies match `rm` whether it was
	// invoked as `rm` or `/bin/rm`.
	Argv []string
	// Original is argv[0] exactly as written when it was normalized, empty
	// otherwise.
	Original string
	// Cwd is the most likely working directory for this command, relative to
	// the hook's cwd; empty means the hook's cwd itself.
	Cwd string
	// Cwds lists every working directory the command may run in (it always
	// contains Cwd). The caller must treat the command as escaping the
	// workspace if any candidate resolves a path outside it.
	Cwds []string
	// Redirects are the files the command's standard streams are redirected
	// to or from; each is a file read or write the policy decides.
	Redirects []Redirect
}

// Unsupported records shell syntax the parser refuses to interpret.
type Unsupported struct {
	Reason  string
	Snippet string
}

// CommandList is the result of parsing one Bash tool invocation.
type CommandList struct {
	Commands    []SimpleCommand
	Unsupported []Unsupported
	// PathTargets are `cd` and `git -C` targets, resolved relative to the
	// hook's cwd, that commands run inside. They are checked against the
	// workspace boundary by the caller.
	PathTargets []string
}

const (
	maxWrapperDepth = 4
	maxCwdBranches  = 16
)

var (
	assignmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	fdPattern         = regexp.MustCompile(`^[0-9]+$`)
)

// SplitShellCommand parses a Bash command string. It never returns an error:
// anything it cannot interpret is listed in Unsupported.
func SplitShellCommand(command string) CommandList {
	return splitShellCommand(command, 0, []string{""})
}

// Redirect is one file redirection attached to a simple command.
type Redirect struct {
	// Kind is "read" for `< file` and "write" for `> file`, `>> file`,
	// `2> file`, and `&> file`.
	Kind   string
	Target string
}

type commandGroup struct {
	words     []token
	redirects []Redirect
	prevOp    string
}

func splitShellCommand(command string, depth int, initialCwds []string) CommandList {
	var out CommandList
	if depth > maxWrapperDepth {
		out.Unsupported = append(out.Unsupported, Unsupported{Reason: "shell wrapper nesting too deep", Snippet: truncate(command)})
		return out
	}
	tokens, unsupported := lex(command)
	out.Unsupported = append(out.Unsupported, unsupported...)
	if len(unsupported) > 0 {
		return out
	}
	groups := make([]commandGroup, 0)
	current := commandGroup{}
	for _, tok := range tokens {
		switch tok.kind {
		case tokOp:
			if len(current.words) > 0 {
				groups = append(groups, current)
			}
			current = commandGroup{prevOp: tok.text}
		case tokRedirect:
			current.redirects = append(current.redirects, Redirect{Kind: tok.redirect, Target: tok.text})
		default:
			current.words = append(current.words, tok)
		}
	}
	if len(current.words) > 0 {
		groups = append(groups, current)
	}

	// Each branch is a working directory the shell may be in, tagged with
	// the exit status of the last command that ran there. `&&` runs the next
	// command only in branches that did not fail, `||` only in branches that
	// did not succeed, and the other separators run it everywhere.
	branches := make([]cwdBranch, 0, len(initialCwds))
	for _, c := range uniqueStrings(initialCwds) {
		branches = append(branches, cwdBranch{cwd: c, status: statusUnknown})
	}
	for _, g := range groups {
		running := selectBranches(branches, g.prevOp)
		runCwds := branchCwds(branches, running)
		if len(runCwds) == 0 {
			running = selectBranches(branches, "")
			runCwds = branchCwds(branches, running)
		}
		result := normalizeCommand(g.words, depth, runCwds)
		for i := range result.commands {
			result.commands[i].Redirects = append(result.commands[i].Redirects, g.redirects...)
		}
		out.Commands = append(out.Commands, result.commands...)
		out.Unsupported = append(out.Unsupported, result.findings...)
		out.PathTargets = append(out.PathTargets, result.targets...)
		if result.cd != nil {
			next := make([]cwdBranch, 0, len(branches)*2)
			for i, b := range branches {
				if !running[i] {
					next = append(next, b)
					continue
				}
				target := joinCwd(b.cwd, *result.cd)
				out.PathTargets = append(out.PathTargets, target)
				next = append(next, cwdBranch{cwd: target, status: statusOK}, cwdBranch{cwd: b.cwd, status: statusFailed})
			}
			branches = dedupeBranches(next)
		} else {
			for i := range branches {
				if running[i] {
					branches[i].status = statusUnknown
				}
			}
			branches = dedupeBranches(branches)
		}
		if len(branches) > maxCwdBranches {
			out.Unsupported = append(out.Unsupported, Unsupported{Reason: "too many possible working directories", Snippet: truncate(command)})
			return out
		}
	}
	out.PathTargets = uniqueStrings(out.PathTargets)
	return out
}

type branchStatus int

const (
	statusUnknown branchStatus = iota
	statusOK
	statusFailed
)

type cwdBranch struct {
	cwd    string
	status branchStatus
}

func selectBranches(branches []cwdBranch, prevOp string) []bool {
	running := make([]bool, len(branches))
	for i, b := range branches {
		switch prevOp {
		case "&&":
			running[i] = b.status != statusFailed
		case "||":
			running[i] = b.status != statusOK
		default:
			running[i] = true
		}
	}
	return running
}

func branchCwds(branches []cwdBranch, running []bool) []string {
	cwds := make([]string, 0, len(branches))
	for i, b := range branches {
		if running[i] {
			cwds = append(cwds, b.cwd)
		}
	}
	cwds = uniqueStrings(cwds)
	sort.Strings(cwds)
	return cwds
}

func dedupeBranches(in []cwdBranch) []cwdBranch {
	seen := make(map[cwdBranch]struct{}, len(in))
	out := make([]cwdBranch, 0, len(in))
	for _, b := range in {
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		out = append(out, b)
	}
	return out
}

type tokenKind int

const (
	tokWord tokenKind = iota
	tokOp
	tokRedirect
)

type token struct {
	kind   tokenKind
	text   string
	quoted bool
	// expands marks a word that carries a simple parameter expansion
	// (`$NAME`, `${NAME}`, `$?`); the normalizer accepts it only for
	// print-only commands.
	expands bool
	// redirect is "read" or "write" for tokRedirect tokens.
	redirect string
}

// parameterExpansion matches the expansions the lexer keeps as text:
// `$NAME`, `${NAME}`, and `$?`. Everything else (`$(...)`, backticks,
// positional and special parameters, `${NAME:-...}` modifiers) is refused.
var parameterExpansion = regexp.MustCompile(`^\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*|\?)`)

// printOnlyPrograms may receive parameter expansions in their arguments:
// they only print or test their arguments and never run, open, or write
// anything on their own (a redirection is decided separately).
var printOnlyPrograms = map[string]bool{"echo": true, "printf": true, "printenv": true, "test": true, "[": true, "true": true, "false": true}

func isShellBlank(r rune) bool {
	// POSIX field splitting uses IFS (space, tab, newline); other Unicode
	// spaces are ordinary characters to the shell and must stay in the word.
	return r == ' ' || r == '\t' || r == '\r' || r == '\v' || r == '\f'
}

func lex(command string) ([]token, []Unsupported) {
	var tokens []token
	var findings []Unsupported
	var word strings.Builder
	quoted := false
	haveWord := false
	expands := false
	runes := []rune(command)
	n := len(runes)

	reject := func(reason string, at int) ([]token, []Unsupported) {
		end := at + 24
		if end > n {
			end = n
		}
		start := at - 8
		if start < 0 {
			start = 0
		}
		findings = append(findings, Unsupported{Reason: reason, Snippet: truncate(string(runes[start:end]))})
		return nil, findings
	}
	endWord := func() {
		if haveWord {
			tokens = append(tokens, token{kind: tokWord, text: word.String(), quoted: quoted, expands: expands})
		}
		word.Reset()
		quoted = false
		haveWord = false
		expands = false
	}
	// expansionAt keeps a simple parameter expansion starting at runes[i]
	// as literal text and reports how many runes it consumed, or 0 when the
	// `$` starts something the parser refuses.
	expansionAt := func(i int) int {
		m := parameterExpansion.FindString(string(runes[i:min(n, i+80)]))
		return len([]rune(m))
	}
	// redirectTarget reads the file operand of a redirection. Quotes around
	// the whole operand are stripped; an operand that still carries a quote,
	// an expansion, or a substitution is refused, because the file it names
	// cannot be known.
	consumeRedirectTarget := func(i int) (string, int) {
		for i < n && isShellBlank(runes[i]) {
			i++
		}
		var b strings.Builder
		for i < n && !isShellBlank(runes[i]) && runes[i] != '\n' && !strings.ContainsRune(";&|<>()", runes[i]) {
			b.WriteRune(runes[i])
			i++
		}
		return b.String(), i
	}

	redirectTarget := func(i int) (string, int, bool) {
		target, next := consumeRedirectTarget(i)
		if len(target) >= 2 && ((target[0] == '"' && target[len(target)-1] == '"') || (target[0] == '\'' && target[len(target)-1] == '\'')) {
			target = target[1 : len(target)-1]
		}
		if target == "" || strings.ContainsAny(target, "$`\"'\\") {
			return target, next, false
		}
		return target, next, true
	}
	emitOp := func(text string) {
		endWord()
		tokens = append(tokens, token{kind: tokOp, text: text})
	}
	for i := 0; i < n; i++ {
		r := runes[i]
		switch {
		case r == 0:
			return reject("NUL byte", i)
		case r == '\\':
			if i+1 >= n {
				word.WriteRune(r)
				haveWord = true
				continue
			}
			i++
			if runes[i] == '\n' {
				endWord()
				continue
			}
			word.WriteRune(runes[i])
			haveWord = true
		case r == '\'':
			j := i + 1
			for j < n && runes[j] != '\'' {
				j++
			}
			if j >= n {
				return reject("unterminated single quote", i)
			}
			word.WriteString(string(runes[i+1 : j]))
			quoted = true
			haveWord = true
			i = j
		case r == '"':
			j := i + 1
			for j < n && runes[j] != '"' {
				switch runes[j] {
				case '\\':
					// Inside double quotes a backslash only escapes $ ` " \ and
					// newline; before any other character it is literal.
					if j+1 < n && strings.ContainsRune("$`\"\\\n", runes[j+1]) {
						j++
						if runes[j] == '$' || runes[j] == '`' {
							word.WriteRune(runes[j])
						} else if runes[j] != '\n' {
							word.WriteRune(runes[j])
						}
					} else {
						word.WriteRune('\\')
					}
				case '$':
					if k := expansionAt(j); k > 0 {
						word.WriteString(string(runes[j : j+k]))
						expands = true
						j += k - 1
						break
					}
					return reject("variable or command substitution inside double quotes", j)
				case '`':
					return reject("command substitution inside double quotes", j)
				default:
					word.WriteRune(runes[j])
				}
				j++
			}
			if j >= n {
				return reject("unterminated double quote", i)
			}
			quoted = true
			haveWord = true
			i = j
		case r == '$':
			if k := expansionAt(i); k > 0 {
				word.WriteString(string(runes[i : i+k]))
				expands = true
				haveWord = true
				i += k - 1
				continue
			}
			return reject("variable or command substitution", i)
		case r == '`':
			return reject("command substitution", i)
		case r == '(' || r == ')':
			return reject("subshell or process substitution", i)
		case r == '{' || r == '}':
			return reject("brace grouping or expansion", i)
		case r == '#' && !haveWord:
			for i < n && runes[i] != '\n' {
				i++
			}
			i--
		case r == '\n':
			emitOp(";")
		case isShellBlank(r):
			endWord()
		case r == ';':
			if i+1 < n && runes[i+1] == ';' {
				return reject("case terminator", i)
			}
			emitOp(";")
		case r == '&':
			if i+1 < n && runes[i+1] == '&' {
				emitOp("&&")
				i++
				continue
			}
			if i+1 < n && runes[i+1] == '>' {
				j := i + 2
				if j < n && runes[j] == '>' {
					j++
				}
				endWord()
				target, next, ok := redirectTarget(j)
				if !ok {
					return reject("redirection to a file that cannot be named", i)
				}
				if target != "/dev/null" {
					tokens = append(tokens, token{kind: tokRedirect, text: target, redirect: "write"})
				}
				i = next - 1
				continue
			}
			emitOp("&")
		case r == '|':
			if i+1 < n && (runes[i+1] == '|' || runes[i+1] == '&') {
				emitOp(string(runes[i : i+2]))
				i++
				continue
			}
			emitOp("|")
		case r == '<':
			if haveWord && !quoted && fdPattern.MatchString(word.String()) {
				word.Reset()
				haveWord = false
			} else {
				endWord()
			}
			j := i + 1
			if j < n && runes[j] == '<' {
				if j+1 < n && runes[j+1] == '<' {
					// A here-string feeds literal text on stdin; it is data,
					// unless it carries a substitution.
					target, next := consumeRedirectTarget(j + 2)
					if strings.ContainsAny(target, "$`") {
						return reject("substitution inside a here-string", i)
					}
					i = next - 1
					continue
				}
				return reject("heredoc", i)
			}
			if j < n && runes[j] == '(' {
				return reject("process substitution", i)
			}
			if j < n && runes[j] == '&' {
				target, next := consumeRedirectTarget(j + 1)
				if fdPattern.MatchString(target) || target == "-" {
					i = next - 1
					continue
				}
				return reject("input redirection from a descriptor that cannot be named", i)
			}
			kind := "read"
			if j < n && runes[j] == '>' {
				kind = "write"
				j++
			}
			target, next, ok := redirectTarget(j)
			if !ok {
				return reject("redirection from a file that cannot be named", i)
			}
			if target != "/dev/null" {
				tokens = append(tokens, token{kind: tokRedirect, text: target, redirect: kind})
			}
			i = next - 1
		case r == '>':
			if haveWord && !quoted && fdPattern.MatchString(word.String()) {
				word.Reset()
				haveWord = false
			} else {
				endWord()
			}
			j := i + 1
			if j < n && runes[j] == '>' {
				j++
			}
			if j < n && runes[j] == '|' {
				j++
			}
			if j < n && runes[j] == '&' {
				target, next := consumeRedirectTarget(j + 1)
				if fdPattern.MatchString(target) || target == "-" || target == "/dev/null" {
					i = next - 1
					continue
				}
				return reject("output redirection to a file", i)
			}
			if j < n && runes[j] == '(' {
				return reject("process substitution", i)
			}
			target, next, ok := redirectTarget(j)
			if !ok {
				return reject("redirection to a file that cannot be named", i)
			}
			if target != "/dev/null" {
				tokens = append(tokens, token{kind: tokRedirect, text: target, redirect: "write"})
			}
			i = next - 1
		default:
			word.WriteRune(r)
			haveWord = true
		}
	}
	endWord()
	return tokens, findings
}

type normalizedCommand struct {
	commands []SimpleCommand
	findings []Unsupported
	targets  []string
	cd       *string
}

func unsupported(reason, snippet string) normalizedCommand {
	return normalizedCommand{findings: []Unsupported{{Reason: reason, Snippet: snippet}}}
}

func normalizeCommand(words []token, depth int, cwds []string) normalizedCommand {
	argv := make([]string, 0, len(words))
	for _, w := range words {
		argv = append(argv, w.text)
	}
	if len(argv) == 0 {
		return normalizedCommand{}
	}
	snippet := truncate(strings.Join(argv, " "))
	if !words[0].quoted && assignmentPattern.MatchString(argv[0]) {
		return unsupported("environment assignment prefix", snippet)
	}
	expandsAny := false
	for _, w := range words {
		expandsAny = expandsAny || w.expands
	}
	if words[0].expands {
		return unsupported("variable expansion in the command name", snippet)
	}
	// Unwrap transparent wrappers.
	for guard := 0; guard < 8 && len(argv) > 0; guard++ {
		name := baseName(argv[0])
		switch name {
		case "env":
			if len(argv) == 1 {
				// A bare `env` prints the environment; it wraps nothing.
				break
			}
			if strings.HasPrefix(argv[1], "-") || assignmentPattern.MatchString(argv[1]) {
				return unsupported("env with options or assignments", snippet)
			}
			argv = argv[1:]
			continue
		case "command", "exec", "nohup", "time":
			if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
				return unsupported(name+" wrapper with options", snippet)
			}
			argv = argv[1:]
			continue
		case "nice":
			rest := argv[1:]
			if len(rest) > 0 && rest[0] == "-n" && len(rest) > 1 {
				rest = rest[2:]
			} else if len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
				rest = rest[1:]
			}
			if len(rest) == 0 {
				return unsupported("nice without a command", snippet)
			}
			argv = rest
			continue
		case "sudo", "doas", "su", "pkexec", "runas":
			return unsupported("privilege escalation", snippet)
		case "eval", "source", ".", "xargs", "parallel", "watch":
			return unsupported(name+" executes commands from arguments or input", snippet)
		case "sh", "bash", "dash", "zsh", "ksh", "fish":
			if expandsAny {
				return unsupported("variable expansion inside a shell wrapper", snippet)
			}
			inner, ok, findings := unwrapPOSIXShell(argv, snippet)
			if len(findings) > 0 {
				return normalizedCommand{findings: findings}
			}
			if ok {
				nested := splitShellCommand(inner, depth+1, cwds)
				return normalizedCommand{commands: nested.Commands, findings: nested.Unsupported, targets: nested.PathTargets}
			}
		case "pwsh", "powershell":
			if expandsAny {
				return unsupported("variable expansion inside a shell wrapper", snippet)
			}
			inner, ok, findings := unwrapPowerShell(argv, snippet)
			if len(findings) > 0 {
				return normalizedCommand{findings: findings}
			}
			if ok {
				nested := splitShellCommand(inner, depth+1, cwds)
				return normalizedCommand{commands: nested.Commands, findings: nested.Unsupported, targets: nested.PathTargets}
			}
		case "cmd":
			if len(argv) >= 2 && strings.EqualFold(argv[1], "/c") {
				if expandsAny {
					return unsupported("variable expansion inside a shell wrapper", snippet)
				}
				if len(argv) != 3 {
					return unsupported("cmd /c with more than one argument", snippet)
				}
				nested := splitShellCommand(argv[2], depth+1, cwds)
				return normalizedCommand{commands: nested.Commands, findings: nested.Unsupported, targets: nested.PathTargets}
			}
		}
		break
	}
	if len(argv) == 0 {
		return normalizedCommand{}
	}
	name := baseName(argv[0])
	if expandsAny && !printOnlyPrograms[name] {
		return unsupported("variable expansion in an argument of "+name, snippet)
	}
	original := ""
	if argv[0] != name {
		original = argv[0]
	}
	switch name {
	case "cd":
		target := "~"
		if len(argv) > 1 {
			target = argv[1]
		}
		if len(argv) > 2 {
			return unsupported("cd with multiple arguments", snippet)
		}
		if target == "-" {
			return unsupported("cd to previous directory", snippet)
		}
		return normalizedCommand{cd: &target}
	case "pushd", "popd", "export", "unset", "set", "alias", "unalias", "shopt", "ulimit", "umask", "trap", "declare", "typeset", "local", "readonly", "let", "builtin", "enable", "hash":
		return unsupported("shell builtin that changes shell state", snippet)
	}
	targets := []string{}
	if name == "git" {
		var findings []Unsupported
		argv, targets, findings = normalizeGitGlobals(argv, cwds, snippet)
		if len(findings) > 0 {
			return normalizedCommand{findings: findings}
		}
	}
	if name == "find" {
		for _, arg := range argv[1:] {
			switch arg {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete":
				return unsupported("find executes commands or deletes", snippet)
			}
		}
	}
	if argv[0] != name {
		argv = append([]string{name}, argv[1:]...)
	}
	return normalizedCommand{
		commands: []SimpleCommand{{Argv: argv, Original: original, Cwd: cwds[0], Cwds: append([]string{}, cwds...)}},
		targets:  targets,
	}
}

func unwrapPOSIXShell(argv []string, snippet string) (string, bool, []Unsupported) {
	sawC := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if sawC {
			if i != len(argv)-1 {
				return "", false, []Unsupported{{Reason: "shell -c with positional parameters", Snippet: snippet}}
			}
			return arg, true, nil
		}
		switch {
		case arg == "--":
			continue
		case arg == "-o":
			if i+1 < len(argv) && argv[i+1] == "pipefail" {
				i++
				continue
			}
			return "", false, []Unsupported{{Reason: "shell option " + arg, Snippet: snippet}}
		case arg == "--login" || arg == "--noprofile" || arg == "--norc" || arg == "--posix":
			continue
		case strings.HasPrefix(arg, "-") && len(arg) > 1 && !strings.HasPrefix(arg, "--"):
			flags := arg[1:]
			for _, f := range flags {
				if !strings.ContainsRune("celuxp", f) {
					return "", false, []Unsupported{{Reason: "shell option " + arg, Snippet: snippet}}
				}
			}
			if strings.ContainsRune(flags, 'c') {
				sawC = true
			}
		default:
			// `bash script.sh` runs a file: leave it as a plain command.
			return "", false, nil
		}
	}
	if sawC {
		return "", false, []Unsupported{{Reason: "shell -c without a command string", Snippet: snippet}}
	}
	return "", false, nil
}

func unwrapPowerShell(argv []string, snippet string) (string, bool, []Unsupported) {
	for i := 1; i < len(argv); i++ {
		lower := strings.ToLower(argv[i])
		switch lower {
		case "-command", "-c":
			if i+1 >= len(argv) {
				return "", false, []Unsupported{{Reason: "powershell -Command without a command string", Snippet: snippet}}
			}
			if i+1 != len(argv)-1 {
				return "", false, []Unsupported{{Reason: "powershell -Command with more than one argument", Snippet: snippet}}
			}
			return argv[i+1], true, nil
		case "-encodedcommand", "-ec", "-e", "-enc":
			return "", false, []Unsupported{{Reason: "powershell encoded command", Snippet: snippet}}
		case "-noprofile", "-nologo", "-noninteractive", "-nol", "-mta", "-sta":
			continue
		case "-executionpolicy", "-inputformat", "-outputformat":
			i++
		default:
			return "", false, nil
		}
	}
	return "", false, nil
}

// normalizeGitGlobals strips git's harmless global options and rejects the
// ones that execute configured commands or relocate the repository:
// `-c key=value` (core.pager, alias.*, core.sshCommand, core.hooksPath, ...),
// `--config-env`, `--exec-path`, `--git-dir`, `--work-tree`, `--namespace`.
// `-C <dir>` is kept as a working-directory target for the boundary check.
func normalizeGitGlobals(argv []string, cwds []string, snippet string) ([]string, []string, []Unsupported) {
	targets := []string{}
	out := []string{"git"}
	i := 1
	for i < len(argv) {
		arg := argv[i]
		switch {
		case arg == "-C":
			if i+1 >= len(argv) {
				return nil, nil, []Unsupported{{Reason: "git -C without a directory", Snippet: snippet}}
			}
			for _, c := range cwds {
				targets = append(targets, joinCwd(c, argv[i+1]))
			}
			i += 2
		case arg == "-c" || strings.HasPrefix(arg, "--config-env"):
			return nil, nil, []Unsupported{{Reason: "git configuration override can execute commands", Snippet: snippet}}
		case arg == "--exec-path" || strings.HasPrefix(arg, "--exec-path="), arg == "--git-dir" || strings.HasPrefix(arg, "--git-dir="), arg == "--work-tree" || strings.HasPrefix(arg, "--work-tree="), arg == "--namespace" || strings.HasPrefix(arg, "--namespace="), arg == "--super-prefix" || strings.HasPrefix(arg, "--super-prefix="), arg == "--attr-source" || strings.HasPrefix(arg, "--attr-source="):
			return nil, nil, []Unsupported{{Reason: "git option relocates the repository or its helpers", Snippet: snippet}}
		case arg == "--no-pager", arg == "-p", arg == "--paginate", arg == "-P", arg == "--no-optional-locks", arg == "--bare", arg == "--literal-pathspecs", arg == "--glob-pathspecs", arg == "--noglob-pathspecs", arg == "--icase-pathspecs", arg == "--no-replace-objects", arg == "--no-advice", arg == "--no-lazy-fetch":
			i++
		default:
			out = append(out, argv[i:]...)
			return out, uniqueStrings(targets), nil
		}
	}
	return out, uniqueStrings(targets), nil
}

func baseName(command string) string {
	command = strings.TrimSpace(command)
	command = strings.ReplaceAll(command, "\\", "/")
	if idx := strings.LastIndex(command, "/"); idx >= 0 {
		command = command[idx+1:]
	}
	return command
}

// joinCwd resolves target against cwd, both expressed relative to the hook's
// cwd. Absolute and home-relative targets are kept as written so the caller
// can classify them.
func joinCwd(cwd, target string) string {
	if target == "" {
		return cwd
	}
	if filepath.IsAbs(target) || strings.HasPrefix(target, "~") || strings.HasPrefix(target, "/") {
		return target
	}
	if cwd == "" {
		return filepath.Clean(target)
	}
	if filepath.IsAbs(cwd) || strings.HasPrefix(cwd, "~") {
		return filepath.Join(cwd, target)
	}
	return filepath.Clean(filepath.Join(cwd, target))
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func truncate(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

func (c SimpleCommand) String() string {
	return fmt.Sprintf("%v", c.Argv)
}
