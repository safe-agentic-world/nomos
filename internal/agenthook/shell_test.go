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
		{name: "git -c config stripped", cmd: "git -c core.pager=cat log -1", want: [][]string{{"git", "log", "-1"}}},
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
		{"variable", "rm -rf $HOME", "variable or command substitution"},
		{"variable in double quotes", `rm -rf "$HOME"`, "inside double quotes"},
		{"command substitution", "echo $(rm -rf /)", "variable or command substitution"},
		{"backticks", "echo `rm -rf /`", "command substitution"},
		{"cygpath substitution", `rm -rf "$(cygpath -u 'C:\')"`, "inside double quotes"},
		{"heredoc", "cat <<EOF\nrm -rf /\nEOF", "input redirection"},
		{"input redirect", "python3 < script.py", "input redirection"},
		{"output redirect", "echo x > ~/.bashrc", "output redirection to a file"},
		{"append redirect", "echo x >> notes.txt", "output redirection to a file"},
		{"all output redirect", "make &> build.log", "output redirection to a file"},
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
		{"export", "export PATH=/tmp:$PATH", "variable or command substitution"},
		{"export literal", "export FOO=bar", "shell builtin"},
		{"source", "source ./env.sh", "executes commands"},
		{"dot source", ". ./env.sh", "executes commands"},
		{"unterminated quote", "echo 'oops", "unterminated single quote"},
		{"case terminator", "case x in a) ;; esac", "subshell"},
		{"shell -c positional", `bash -c 'echo $1' _ arg`, "positional parameters"},
		{"shell unknown flag", "bash -r -c 'ls'", "shell option -r"},
		{"cd dash", "cd - && ls", "cd to previous directory"},
		{"pushd", "pushd /tmp", "shell builtin"},
		{"env with assignment", "env FOO=1 make", "env with options or assignments"},
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
