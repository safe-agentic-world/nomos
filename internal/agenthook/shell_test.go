package agenthook

import (
	"reflect"
	"strings"
	"testing"
)

func argvs(list CommandList) [][]string {
	out := make([][]string, 0, len(list.Commands))
	for _, c := range list.Commands {
		out = append(out, c.Argv)
	}
	return out
}

func reasons(list CommandList) []string {
	out := make([]string, 0, len(list.Unsupported))
	for _, u := range list.Unsupported {
		out = append(out, u.Reason)
	}
	return out
}

func TestSplitShellCommandSimpleAndChained(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want [][]string
	}{
		{"single", "git status", [][]string{{"git", "status"}}},
		{"and chain", "npm test && git push origin main", [][]string{{"npm", "test"}, {"git", "push", "origin", "main"}}},
		{"or and semicolon", "go build || echo failed; ls", [][]string{{"go", "build"}, {"echo", "failed"}, {"ls"}}},
		{"pipe", "cat README.md | grep -i nomos", [][]string{{"cat", "README.md"}, {"grep", "-i", "nomos"}}},
		{"newlines", "go vet ./...\ngo test ./...", [][]string{{"go", "vet", "./..."}, {"go", "test", "./..."}}},
		{"double quotes", `git commit -m "hello world"`, [][]string{{"git", "commit", "-m", "hello world"}}},
		{"single quotes keep dollar", `echo '$HOME'`, [][]string{{"echo", "$HOME"}}},
		{"escaped space", `ls my\ file`, [][]string{{"ls", "my file"}}},
		{"background", "sleep 5 &", [][]string{{"sleep", "5"}}},
		{"comment stripped", "ls # list files; rm -rf /", [][]string{{"ls"}}},
		{"incident home wipe tokens", "rm -rf tests/ patches/ plan/ ~/", [][]string{{"rm", "-rf", "tests/", "patches/", "plan/", "~/"}}},
		{"fd dup and devnull dropped", "go test ./... >/dev/null 2>&1 | tail -n 5", [][]string{{"go", "test", "./..."}, {"tail", "-n", "5"}}},
		{"stderr to stdout", "make 2>&1", [][]string{{"make"}}},
		{"stdout to stderr", "echo x >&2", [][]string{{"echo", "x"}}},
		{"line continuation", "go test \\\n ./...", [][]string{{"go", "test", "./..."}}},
		{"glob kept literal", "rm -rf *", [][]string{{"rm", "-rf", "*"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := SplitShellCommand(tc.cmd)
			if len(list.Unsupported) != 0 {
				t.Fatalf("unexpected unsupported: %+v", list.Unsupported)
			}
			if got := argvs(list); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSplitShellCommandUnwrapsWrappersAndNormalizesNames(t *testing.T) {
	cases := []struct {
		name         string
		cmd          string
		want         [][]string
		wantOriginal string
		wantTargets  []string
	}{
		{name: "bash -c compound", cmd: `bash -c "rm -rf /tmp/x && echo done"`, want: [][]string{{"rm", "-rf", "/tmp/x"}, {"echo", "done"}}},
		{name: "sh -lc", cmd: `sh -lc 'go test ./...'`, want: [][]string{{"go", "test", "./..."}}},
		{name: "by path rm", cmd: "/bin/rm -rf ~/", want: [][]string{{"rm", "-rf", "~/"}}, wantOriginal: "/bin/rm"},
		{name: "usr bin git", cmd: "/usr/bin/git push --force", want: [][]string{{"git", "push", "--force"}}, wantOriginal: "/usr/bin/git"},
		{name: "env wrapper", cmd: "env go test ./...", want: [][]string{{"go", "test", "./..."}}},
		{name: "time wrapper", cmd: "time go build ./...", want: [][]string{{"go", "build", "./..."}}},
		{name: "nice wrapper", cmd: "nice -n 10 make", want: [][]string{{"make"}}},
		{name: "git -C strips option and records target", cmd: "git -C /tmp/other push", want: [][]string{{"git", "push"}}, wantTargets: []string{"/tmp/other"}},
		{name: "git no-pager stripped", cmd: "git --no-pager diff", want: [][]string{{"git", "diff"}}},
		{name: "pwsh command", cmd: `pwsh -NoProfile -Command "git status"`, want: [][]string{{"git", "status"}}},
		{name: "cmd /c", cmd: `cmd /c "git status"`, want: [][]string{{"git", "status"}}},
		{name: "bash script file stays plain", cmd: "bash scripts/build.sh", want: [][]string{{"bash", "scripts/build.sh"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := SplitShellCommand(tc.cmd)
			if len(list.Unsupported) != 0 {
				t.Fatalf("unexpected unsupported: %+v", list.Unsupported)
			}
			if got := argvs(list); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			if tc.wantOriginal != "" && list.Commands[0].Original != tc.wantOriginal {
				t.Fatalf("original: got %q want %q", list.Commands[0].Original, tc.wantOriginal)
			}
			if tc.wantTargets != nil && !reflect.DeepEqual(list.PathTargets, tc.wantTargets) {
				t.Fatalf("targets: got %v want %v", list.PathTargets, tc.wantTargets)
			}
		})
	}
}

func TestSplitShellCommandRefusesUnsafeSyntaxFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		cmd    string
		reason string
	}{
		{"variable", "rm -rf $HOME", "variable expansion in an argument of rm"},
		{"variable in double quotes", `rm -rf "$HOME"`, "variable expansion in an argument of rm"},
		{"command substitution", "echo $(rm -rf /)", "variable or command substitution"},
		{"backticks", "echo `rm -rf /`", "command substitution"},
		{"cygpath substitution", `rm -rf "$(cygpath -u 'C:\')"`, "inside double quotes"},
		{"heredoc", "cat <<EOF\nrm -rf /\nEOF", "heredoc"},
		{"quoted redirect target with a space", `cat > "out file.txt"`, "cannot be named"},
		{"redirect target with expansion", `cat > "$OUT"`, "cannot be named"},
		{"here-string with substitution", `cat <<< "$X"`, "here-string"},
		{"expansion in a shell wrapper", `bash -c "echo $X"`, "shell wrapper"},
		{"expansion as the command", "$CMD --version", "command name"},
		{"positional parameter", "echo $1", "variable or command substitution"},
		{"special parameter", "echo $$", "variable or command substitution"},
		{"expansion modifier", "echo ${X:-y}", "variable or command substitution"},
		{"expansion in rm", "rm -rf $DIR/*", "variable expansion in an argument of rm"},
		{"subshell", "(cd /tmp && rm -rf x)", "subshell"},
		{"brace group", "{ rm -rf x; }", "brace grouping"},
		{"assignment prefix", "HOME=/ rm -rf ~", "environment assignment prefix"},
		{"sudo", "sudo rm -rf /", "privilege escalation"},
		{"doas", "doas reboot", "privilege escalation"},
		{"eval", `eval "rm -rf /"`, "executes commands"},
		{"xargs", "find . -name '*.log' | xargs rm", "executes commands"},
		{"find delete", "find . -name '*.log' -delete", "find executes commands or deletes"},
		{"find exec", `find . -type f -exec rm {} \;`, "brace grouping"},
		{"trap", "trap 'rm -rf x' EXIT", "shell builtin"},
		{"export", "export PATH=/tmp:$PATH", "variable expansion"},
		{"export literal", "export FOO=bar", "shell builtin"},
		{"for loop", "for f in *.go; do gofmt -l $f; done", "shell control flow"},
		{"if statement", "if test -f x; then cat x; fi", "shell control flow"},
		{"source", "source ./env.sh", "executes commands"},
		{"dot source", ". ./env.sh", "executes commands"},
		{"unterminated quote", "echo 'oops", "unterminated single quote"},
		{"case terminator", "case x in a) ;; esac", "subshell"},
		{"shell -c positional", `bash -c 'echo $1' _ arg`, "positional parameters"},
		{"shell unknown flag", "bash -r -c 'ls'", "shell option -r"},
		{"cd dash", "cd - && ls", "cd to previous directory"},
		{"pushd", "pushd /tmp", "shell builtin"},
		{"env with assignment", "env FOO=1 make", "env with options or assignments"},
		{"git config override executes commands", "git -c core.pager='touch MARK' log", "git configuration override"},
		{"git alias override", "git -c alias.zz='!touch MARK' zz", "git configuration override"},
		{"git config-env", "git --config-env=core.pager=X log", "git configuration override"},
		{"git exec-path", "git --exec-path=./inside status", "relocates the repository"},
		{"git git-dir", "git --git-dir=.git status", "relocates the repository"},
		{"git work-tree space form", "git --work-tree /tmp status", "relocates the repository"},
		{"powershell multiple command args", "pwsh -Command git status extra", "more than one argument"},
		{"powershell encoded", "powershell -EncodedCommand ZQBjAGgAbwA=", "encoded command"},
		{"cmd /c multiple args", "cmd /c git status extra", "more than one argument"},
		{"nul byte", "ls\x00-la", "NUL byte"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := SplitShellCommand(tc.cmd)
			if len(list.Unsupported) == 0 {
				t.Fatalf("expected unsupported for %q, got commands %v", tc.cmd, argvs(list))
			}
			joined := strings.Join(reasons(list), " | ")
			if !strings.Contains(joined, tc.reason) {
				t.Fatalf("expected reason containing %q, got %q", tc.reason, joined)
			}
		})
	}
}

func TestSplitShellCommandTracksCwdAcrossCd(t *testing.T) {
	list := SplitShellCommand("cd sub/dir && go test ./... ; cd /tmp && rm -rf x")
	if len(list.Unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", list.Unsupported)
	}
	if got := argvs(list); !reflect.DeepEqual(got, [][]string{{"go", "test", "./..."}, {"rm", "-rf", "x"}}) {
		t.Fatalf("argv: %v", got)
	}
	if list.Commands[0].Cwd != "sub/dir" {
		t.Fatalf("first command cwd: %q", list.Commands[0].Cwd)
	}
	if list.Commands[1].Cwd != "/tmp" {
		t.Fatalf("second command cwd: %q", list.Commands[1].Cwd)
	}
	if !reflect.DeepEqual(list.PathTargets, []string{"sub/dir", "/tmp"}) {
		t.Fatalf("targets: %v", list.PathTargets)
	}
	home := SplitShellCommand("cd && ls")
	if !reflect.DeepEqual(home.PathTargets, []string{"~"}) {
		t.Fatalf("bare cd must target home: %v", home.PathTargets)
	}
}

func TestSplitShellCommandNestedWrapperDepthIsBounded(t *testing.T) {
	cmd := "ls"
	for i := 0; i < 6; i++ {
		cmd = "bash -c '" + strings.ReplaceAll(cmd, "'", "'\\''") + "'"
	}
	list := SplitShellCommand(cmd)
	if len(list.Unsupported) == 0 {
		t.Fatal("expected nesting limit to reject deeply nested wrappers")
	}
}

func TestSplitShellCommandTracksPossibleCwdsAcrossFailedCd(t *testing.T) {
	// A real shell keeps running after a failed cd when the separator is ;
	// or ||, so the next command may run in either directory.
	list := SplitShellCommand("cd nope ; cat ../secret.txt")
	if len(list.Unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", list.Unsupported)
	}
	if len(list.Commands) != 1 {
		t.Fatalf("expected one command, got %v", argvs(list))
	}
	if got := list.Commands[0].Cwds; !reflect.DeepEqual(got, []string{"", "nope"}) {
		t.Fatalf("cwd candidates after failed-or-succeeded cd: %v", got)
	}
	orList := SplitShellCommand("cd nope || cat ../secret.txt")
	if got := orList.Commands[0].Cwds; !reflect.DeepEqual(got, []string{""}) {
		t.Fatalf("after `cd || cmd` the command runs only when cd failed: %v", got)
	}
	andList := SplitShellCommand("cd sub && cat ../x")
	if got := andList.Commands[0].Cwds; !reflect.DeepEqual(got, []string{"sub"}) {
		t.Fatalf("after `cd && cmd` the command runs only when cd succeeded: %v", got)
	}
	later := SplitShellCommand("cd sub && ls ; cat ../x")
	if got := later.Commands[1].Cwds; !reflect.DeepEqual(got, []string{"", "sub"}) {
		t.Fatalf("a later command may run in either directory: %v", got)
	}
	chain := SplitShellCommand("cd a || cd b ; ls")
	if got := chain.Commands[0].Cwds; len(got) != 3 {
		t.Fatalf("expected three possible directories (root, a, b), got %v", got)
	}
}

func TestSplitShellCommandBoundsCwdBranches(t *testing.T) {
	cmd := ""
	for i := 0; i < 20; i++ {
		cmd += "cd d" + string(rune('a'+i)) + " ; "
	}
	cmd += "ls"
	list := SplitShellCommand(cmd)
	if len(list.Unsupported) == 0 {
		t.Fatal("expected the working-directory branch bound to trigger")
	}
}

func TestLexFollowsShellQuotingAndWhitespaceRules(t *testing.T) {
	list := SplitShellCommand(`echo "a\.b" "say \"hi\"" 'lit\eral'`)
	if len(list.Unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", list.Unsupported)
	}
	want := []string{"echo", `a\.b`, `say "hi"`, `lit\eral`}
	if got := list.Commands[0].Argv; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	nbsp := SplitShellCommand("ls\u00a0-la")
	if got := nbsp.Commands[0].Argv; !reflect.DeepEqual(got, []string{"ls\u00a0-la"}) {
		t.Fatalf("non-breaking space must not split words: %q", got)
	}
}

func TestSplitShellCommandMapsRedirectionsAndPrintOnlyExpansions(t *testing.T) {
	cases := []struct {
		cmd       string
		argv      [][]string
		redirects [][]Redirect
	}{
		{"python3 < script.py", [][]string{{"python3"}}, [][]Redirect{{{Kind: "read", Target: "script.py"}}}},
		{"echo x > ~/.bashrc", [][]string{{"echo", "x"}}, [][]Redirect{{{Kind: "write", Target: "~/.bashrc"}}}},
		{"echo x >> notes.txt", [][]string{{"echo", "x"}}, [][]Redirect{{{Kind: "write", Target: "notes.txt"}}}},
		{"make &> build.log", [][]string{{"make"}}, [][]Redirect{{{Kind: "write", Target: "build.log"}}}},
		{"go test ./... 2> errors.log", [][]string{{"go", "test", "./..."}}, [][]Redirect{{{Kind: "write", Target: "errors.log"}}}},
		{"go test ./... 2>&1 > /dev/null", [][]string{{"go", "test", "./..."}}, [][]Redirect{nil}},
		{"cat > 'out.txt'", [][]string{{"cat"}}, [][]Redirect{{{Kind: "write", Target: "out.txt"}}}},
		{"sort < input.txt | head -3", [][]string{{"sort"}, {"head", "-3"}}, [][]Redirect{{{Kind: "read", Target: "input.txt"}}, nil}},
		{"cat <<< hello", [][]string{{"cat"}}, [][]Redirect{nil}},
		{"echo $HOME", [][]string{{"echo", "$HOME"}}, [][]Redirect{nil}},
		{`echo "BUILD_DIR=[$BUILD_DIR]"`, [][]string{{"echo", "BUILD_DIR=[$BUILD_DIR]"}}, [][]Redirect{nil}},
		{`printf '%s\n' "${VAR}" $?`, [][]string{{"printf", `%s\n`, "${VAR}", "$?"}}, [][]Redirect{nil}},
		{"printenv $NAME", [][]string{{"printenv", "$NAME"}}, [][]Redirect{nil}},
		{"env echo $X", [][]string{{"echo", "$X"}}, [][]Redirect{nil}},
	}
	for _, tc := range cases {
		list := SplitShellCommand(tc.cmd)
		if len(list.Unsupported) != 0 {
			t.Fatalf("%s: unexpected findings %+v", tc.cmd, list.Unsupported)
		}
		if len(list.Commands) != len(tc.argv) {
			t.Fatalf("%s: got %d commands, want %d: %+v", tc.cmd, len(list.Commands), len(tc.argv), list.Commands)
		}
		for i, cmd := range list.Commands {
			if strings.Join(cmd.Argv, " ") != strings.Join(tc.argv[i], " ") {
				t.Errorf("%s: command %d argv %q, want %q", tc.cmd, i, cmd.Argv, tc.argv[i])
			}
			if len(cmd.Redirects) != len(tc.redirects[i]) {
				t.Errorf("%s: command %d redirects %+v, want %+v", tc.cmd, i, cmd.Redirects, tc.redirects[i])
				continue
			}
			for j, r := range cmd.Redirects {
				if r != tc.redirects[i][j] {
					t.Errorf("%s: command %d redirect %d = %+v, want %+v", tc.cmd, i, j, r, tc.redirects[i][j])
				}
			}
		}
	}
}

func TestSplitShellCommandRecordsRelativeProgramPaths(t *testing.T) {
	cases := map[string]string{
		"./scripts/test.sh --fast":   "scripts/test.sh",
		"scripts/test.sh":            "scripts/test.sh",
		"scripts/../tools/gen.py":    "tools/gen.py",
		"../outside/evil.sh":         "../outside/evil.sh",
		"scripts/../../outside/x.sh": "../outside/x.sh",
		`'.\\scripts\\build.cmd'`:    "scripts/build.cmd",
		"/usr/bin/git status":        "",
		"git status":                 "",
		"~/bin/tool":                 "",
		"C:\\tools\\x.exe":           "",
		"./rm -rf build":             "rm",
		"cd scripts && ./test.sh":    "test.sh",
	}
	for cmd, want := range cases {
		list := SplitShellCommand(cmd)
		if len(list.Unsupported) > 0 {
			t.Fatalf("%q: unexpected findings %+v", cmd, list.Unsupported)
		}
		if len(list.Commands) != 1 {
			t.Fatalf("%q: commands %+v", cmd, list.Commands)
		}
		got := list.Commands[0].Program
		if want == "rm" || want == "test.sh" {
			// The program path is cleaned relative to the command's cwd
			// spelling; the argv keeps the base name.
			if list.Commands[0].Argv[0] != want {
				t.Fatalf("%q: argv[0] = %q", cmd, list.Commands[0].Argv[0])
			}
			continue
		}
		if got != want {
			t.Fatalf("%q: program = %q, want %q", cmd, got, want)
		}
	}
	if list := SplitShellCommand("./rm -rf build"); list.Commands[0].Program != "rm" {
		t.Fatalf("./rm program = %q", list.Commands[0].Program)
	}
	if list := SplitShellCommand("cd scripts && ./test.sh"); list.Commands[0].Program != "test.sh" || list.Commands[0].Cwd != "scripts" {
		t.Fatalf("cd then script: %+v", list.Commands[0])
	}
}

func TestSplitShellCommandRefusesQuotedAssignments(t *testing.T) {
	for _, cmd := range []string{`DIST_DIR="tools/release/npm/dist"`, `FOO='bar' make test`, `X="1" ./scripts/run.sh`, `A=b`} {
		list := SplitShellCommand(cmd)
		if len(list.Unsupported) != 1 || !strings.Contains(list.Unsupported[0].Reason, "assignment") {
			t.Fatalf("%q must be refused as an assignment: %+v / %+v", cmd, list.Commands, list.Unsupported)
		}
	}
	list := SplitShellCommand(`"FOO=bar" --help`)
	if len(list.Unsupported) != 0 || len(list.Commands) != 1 || list.Commands[0].Argv[0] != "FOO=bar" {
		t.Fatalf("a word that begins with a quote is a command name: %+v / %+v", list.Commands, list.Unsupported)
	}
}
