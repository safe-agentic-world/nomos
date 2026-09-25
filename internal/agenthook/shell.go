package agenthook

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// This file turns the single shell command string that coding agents pass to
// their Bash tool into a list of simple commands (argv arrays) that a policy
// can reason about. The parser is deliberately conservative: it understands
// quoting, command lists (&&, ||, ;, |, &, newlines), a few transparent
// wrappers (env, command, exec, nohup, time, nice, bash -c and friends), git's
// global options, and harmless redirections (fd duplication and /dev/null).
// Everything else that could change what actually runs (variable or command
// substitution, heredocs, redirection to files, subshells, environment
// assignments, sudo, eval, xargs, shell builtins that mutate state) is reported
// as unsupported and never silently dropped, so the caller can fail closed.

// SimpleCommand is one command in a command list after normalization.
type SimpleCommand struct {
	// Argv is the normalized argument vector. Argv[0] is the command's base
	// name (directories stripped) so policies match `rm` whether it was
	// invoked as `rm` or `/bin/rm`.
	Argv []string
	// Original is argv[0] exactly as written when it was normalized, empty
	// otherwise.
	Original string
	// Cwd is the effective working directory for this command, relative to
	// the hook's cwd, after any `cd` or `git -C` that precedes it. It is empty
	// when the command runs in the hook's cwd.
	Cwd string
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
	// hook's cwd, that later commands run inside. They are checked against
	// the workspace boundary by the caller.
	PathTargets []string
}

const maxWrapperDepth = 4

var (
	assignmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	fdPattern         = regexp.MustCompile(`^[0-9]+$`)
)

// SplitShellCommand parses a Bash command string. It never returns an error:
// anything it cannot interpret is listed in Unsupported.
func SplitShellCommand(command string) CommandList {
	return splitShellCommand(command, 0, "")
}

func splitShellCommand(command string, depth int, cwd string) CommandList {
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
	current := make([]token, 0)
	flush := func() {
		if len(current) == 0 {
			return
		}
		words := current
		current = nil
		cmds, findings, targets, nextCwd := normalizeCommand(words, depth, cwd)
		out.Commands = append(out.Commands, cmds...)
		out.Unsupported = append(out.Unsupported, findings...)
		out.PathTargets = append(out.PathTargets, targets...)
		cwd = nextCwd
	}
	for _, tok := range tokens {
		if tok.kind == tokOp {
			flush()
			continue
		}
		current = append(current, tok)
	}
	flush()
	return out
}

type tokenKind int

const (
	tokWord tokenKind = iota
	tokOp
)

type token struct {
	kind   tokenKind
	text   string
	quoted bool
}

func lex(command string) ([]token, []Unsupported) {
	var tokens []token
	var findings []Unsupported
	var word strings.Builder
	quoted := false
	haveWord := false
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
			tokens = append(tokens, token{kind: tokWord, text: word.String(), quoted: quoted})
		}
		word.Reset()
		quoted = false
		haveWord = false
	}
	emitOp := func(text string) {
		endWord()
		tokens = append(tokens, token{kind: tokOp, text: text})
	}
	// consumeRedirectTarget reads the word after a redirection operator.
	consumeRedirectTarget := func(i int) (string, int) {
		for i < n && (runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
		var b strings.Builder
		for i < n && !unicode.IsSpace(runes[i]) && !strings.ContainsRune(";&|<>()", runes[i]) {
			b.WriteRune(runes[i])
			i++
		}
		return b.String(), i
	}

	for i := 0; i < n; i++ {
		r := runes[i]
		switch {
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
					if j+1 < n {
						j++
						word.WriteRune(runes[j])
					}
				case '$':
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
		case unicode.IsSpace(r):
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
				// &> file or &>> file: all output to file.
				j := i + 2
				if j < n && runes[j] == '>' {
					j++
				}
				target, next := consumeRedirectTarget(j)
				if target != "/dev/null" {
					return reject("output redirection to a file", i)
				}
				endWord()
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
			return reject("input redirection, heredoc, or process substitution", i)
		case r == '>':
			// Optional fd prefix is the current word if it is all digits.
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
				// >&N duplicates a descriptor; >&word redirects to a file.
				target, next := consumeRedirectTarget(j + 1)
				if fdPattern.MatchString(target) || target == "-" {
					i = next - 1
					continue
				}
				if target == "/dev/null" {
					i = next - 1
					continue
				}
				return reject("output redirection to a file", i)
			}
			if j < n && runes[j] == '(' {
				return reject("process substitution", i)
			}
			target, next := consumeRedirectTarget(j)
			if target != "/dev/null" {
				return reject("output redirection to a file", i)
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

func normalizeCommand(words []token, depth int, cwd string) ([]SimpleCommand, []Unsupported, []string, string) {
	argv := make([]string, 0, len(words))
	for _, w := range words {
		argv = append(argv, w.text)
	}
	if len(argv) == 0 {
		return nil, nil, nil, cwd
	}
	snippet := truncate(strings.Join(argv, " "))
	if !words[0].quoted && assignmentPattern.MatchString(argv[0]) {
		return nil, []Unsupported{{Reason: "environment assignment prefix", Snippet: snippet}}, nil, cwd
	}
	original := ""
	// Unwrap transparent wrappers.
	for guard := 0; guard < 8 && len(argv) > 0; guard++ {
		name := baseName(argv[0])
		switch name {
		case "env":
			if len(argv) < 2 || strings.HasPrefix(argv[1], "-") || assignmentPattern.MatchString(argv[1]) {
				return nil, []Unsupported{{Reason: "env with options or assignments", Snippet: snippet}}, nil, cwd
			}
			argv = argv[1:]
			continue
		case "command", "exec", "nohup", "time":
			if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
				return nil, []Unsupported{{Reason: name + " wrapper with options", Snippet: snippet}}, nil, cwd
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
				return nil, []Unsupported{{Reason: "nice without a command", Snippet: snippet}}, nil, cwd
			}
			argv = rest
			continue
		case "sudo", "doas", "su", "pkexec", "runas":
			return nil, []Unsupported{{Reason: "privilege escalation", Snippet: snippet}}, nil, cwd
		case "eval", "source", ".", "xargs", "parallel", "watch":
			return nil, []Unsupported{{Reason: name + " executes commands from arguments or input", Snippet: snippet}}, nil, cwd
		case "sh", "bash", "dash", "zsh", "ksh", "fish":
			inner, ok, findings := unwrapPOSIXShell(argv, snippet)
			if len(findings) > 0 {
				return nil, findings, nil, cwd
			}
			if ok {
				nested := splitShellCommand(inner, depth+1, cwd)
				return nested.Commands, nested.Unsupported, nested.PathTargets, cwd
			}
		case "pwsh", "powershell":
			inner, ok, findings := unwrapPowerShell(argv, snippet)
			if len(findings) > 0 {
				return nil, findings, nil, cwd
			}
			if ok {
				nested := splitShellCommand(inner, depth+1, cwd)
				return nested.Commands, nested.Unsupported, nested.PathTargets, cwd
			}
		case "cmd":
			if len(argv) >= 3 && strings.EqualFold(argv[1], "/c") {
				nested := splitShellCommand(strings.Join(argv[2:], " "), depth+1, cwd)
				return nested.Commands, nested.Unsupported, nested.PathTargets, cwd
			}
		}
		break
	}
	if len(argv) == 0 {
		return nil, nil, nil, cwd
	}
	name := baseName(argv[0])
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
			return nil, []Unsupported{{Reason: "cd with multiple arguments", Snippet: snippet}}, nil, cwd
		}
		if target == "-" {
			return nil, []Unsupported{{Reason: "cd to previous directory", Snippet: snippet}}, nil, cwd
		}
		next := joinCwd(cwd, target)
		return nil, nil, []string{next}, next
	case "pushd", "popd", "export", "unset", "set", "alias", "unalias", "shopt", "ulimit", "umask", "trap", "declare", "typeset", "local", "readonly", "let", "builtin", "enable", "hash":
		return nil, []Unsupported{{Reason: "shell builtin that changes shell state", Snippet: snippet}}, nil, cwd
	}
	targets := []string{}
	if name == "git" {
		var findings []Unsupported
		argv, targets, findings = normalizeGitGlobals(argv, cwd, snippet)
		if len(findings) > 0 {
			return nil, findings, nil, cwd
		}
	}
	if name == "find" {
		for _, arg := range argv[1:] {
			switch arg {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete":
				return nil, []Unsupported{{Reason: "find executes commands or deletes", Snippet: snippet}}, nil, cwd
			}
		}
	}
	if argv[0] != name {
		argv = append([]string{name}, argv[1:]...)
	}
	return []SimpleCommand{{Argv: argv, Original: original, Cwd: cwd}}, nil, targets, cwd
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
			return strings.Join(argv[i+1:], " "), true, nil
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

func normalizeGitGlobals(argv []string, cwd, snippet string) ([]string, []string, []Unsupported) {
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
			targets = append(targets, joinCwd(cwd, argv[i+1]))
			i += 2
		case arg == "-c":
			if i+1 >= len(argv) {
				return nil, nil, []Unsupported{{Reason: "git -c without a value", Snippet: snippet}}
			}
			i += 2
		case arg == "--git-dir" || arg == "--work-tree" || arg == "--exec-path" || arg == "--namespace":
			if i+1 >= len(argv) {
				return nil, nil, []Unsupported{{Reason: "git option without a value", Snippet: snippet}}
			}
			if arg != "--namespace" {
				targets = append(targets, joinCwd(cwd, argv[i+1]))
			}
			i += 2
		case strings.HasPrefix(arg, "--git-dir=") || strings.HasPrefix(arg, "--work-tree=") || strings.HasPrefix(arg, "--exec-path="):
			targets = append(targets, joinCwd(cwd, arg[strings.Index(arg, "=")+1:]))
			i++
		case strings.HasPrefix(arg, "--namespace="), arg == "--no-pager", arg == "-p", arg == "--paginate", arg == "-P", arg == "--no-optional-locks", arg == "--bare", arg == "--literal-pathspecs", arg == "--glob-pathspecs", arg == "--noglob-pathspecs", arg == "--icase-pathspecs", arg == "--no-replace-objects", arg == "--no-advice":
			i++
		default:
			out = append(out, argv[i:]...)
			return out, targets, nil
		}
	}
	return out, targets, nil
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
// cwd. Absolute and home-relative targets are kept as written so the caller can
// classify them.
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
