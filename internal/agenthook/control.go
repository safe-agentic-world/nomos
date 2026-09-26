package agenthook

import (
	"path"
	"path/filepath"
	"strings"
)

// Control files decide whether and how the hook runs: the harness settings
// that register hooks or switch them off, the policy bundle, and the audit
// log. The policy cannot guard them on its own, because it may be one of
// them and its argv patterns see words rather than the files the words
// resolve to. So the adapter checks every path a call names against them
// after resolving it the way the workspace boundary check does (the
// command's `cd`, `..`, symlinks, `~`, and shell globs), comparing without
// case because the macOS and Windows filesystems do. A file write to an
// audit log is denied. Any other call that could change a control file
// asks: file tools, redirections, patches, and command arguments, except
// for a short list of programs that only read the files they name.

type controlKind int

const (
	controlConfig controlKind = iota
	controlAudit
)

// controlPath is one protected location in every spelling it may resolve to.
type controlPath struct {
	// forms holds the cleaned absolute path and its symlink resolution.
	forms []string
	kind  controlKind
	// tree protects everything at or below the path, not only the path.
	tree bool
}

type controlSet struct {
	paths []controlPath
}

// harnessControlFiles are the files where Claude Code and Codex read hook
// registrations and the switches that turn hooks off (disableAllHooks, the
// Codex hooks feature), relative to the workspace and to the home directory.
var harnessControlFiles = []string{
	".claude/settings.json",
	".claude/settings.local.json",
	".codex/hooks.json",
	".codex/config.toml",
}

// readOnlyPrograms only read the files they name; their redirections are
// decided separately. They count only when invoked by a bare name, since a
// path could be an agent-written script with the same name.
var readOnlyPrograms = map[string]bool{
	"cat": true, "head": true, "tail": true, "wc": true,
	"grep": true, "egrep": true, "fgrep": true,
	"ls": true, "stat": true, "du": true, "diff": true, "cmp": true,
	"md5sum": true, "sha1sum": true, "sha256sum": true, "sha512sum": true, "shasum": true,
	"jq": true, "echo": true, "printf": true, "test": true, "[": true,
	"realpath": true, "readlink": true, "basename": true, "dirname": true,
}

// withControls resolves the control paths once for a whole mapping.
func (o Options) withControls() Options {
	if o.controls == nil {
		o.controls = newControlSet(o)
	}
	return o
}

func newControlSet(opts Options) *controlSet {
	cs := &controlSet{}
	root := cleanAbs(opts.WorkspaceRoot)
	home := cleanAbs(opts.HomeDir)
	add := func(p string, kind controlKind, tree bool) {
		if strings.TrimSpace(p) == "" {
			return
		}
		if !filepath.IsAbs(p) {
			if root == "" {
				return
			}
			p = filepath.Join(root, p)
		}
		p = filepath.Clean(p)
		cs.paths = append(cs.paths, controlPath{forms: controlForms(p), kind: kind, tree: tree})
		// Moving or deleting a directory that holds a control file removes
		// the file, so each directory between it and the workspace (or the
		// home directory) is protected when it is named itself.
		base := ""
		switch {
		case root != "" && strictlyWithin(root, p):
			base = root
		case home != "" && strictlyWithin(home, p):
			base = home
		}
		if base == "" {
			return
		}
		for dir := filepath.Dir(p); strictlyWithin(base, dir); dir = filepath.Dir(dir) {
			cs.paths = append(cs.paths, controlPath{forms: controlForms(dir), kind: kind})
		}
	}
	for _, base := range []string{root, home} {
		if base == "" {
			continue
		}
		for _, rel := range harnessControlFiles {
			add(filepath.Join(base, filepath.FromSlash(rel)), controlConfig, false)
		}
	}
	if root != "" {
		add(filepath.Join(root, ".nomos"), controlAudit, true)
	}
	for _, p := range opts.ControlFiles {
		add(p, controlConfig, false)
	}
	for _, p := range opts.AuditFiles {
		add(p, controlAudit, false)
	}
	return cs
}

func cleanAbs(p string) string {
	if strings.TrimSpace(p) == "" || !filepath.IsAbs(p) {
		return ""
	}
	return filepath.Clean(p)
}

// controlForms lists p and its symlink resolution, so a control file is
// recognized whichever of the two a call's path resolves to.
func controlForms(p string) []string {
	forms := []string{p}
	resolved := p
	if r, err := filepath.EvalSymlinks(p); err == nil {
		resolved = r
	} else {
		resolved = resolveExistingPrefix(p)
	}
	if !samePath(resolved, p) {
		forms = append(forms, resolved)
	}
	return forms
}

// strictlyWithin reports whether p is below base, not base itself.
func strictlyWithin(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != "." && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// controlFinding reports a finding when raw, resolved in the directory the
// command runs in (cmdCwd), names a control file. write marks a file write
// (a file tool, a redirection, or a patch): one to an audit log is denied.
// For a command argument the adapter cannot tell a read from a write, so
// any match asks.
func controlFinding(raw, cmdCwd, what string, write bool, in Input, opts Options) (Finding, bool) {
	c, resolved, ok := opts.controlMatch(raw, cmdCwd, in)
	if !ok {
		return Finding{}, false
	}
	detail := what + " " + strconvQuote(raw) + " resolves to " + strconvQuote(resolved)
	if write && c.kind == controlAudit {
		return Finding{Kind: FindingControlAudit, Detail: detail}, true
	}
	return Finding{Kind: FindingControlConfig, Detail: detail}, true
}

// commandControlFinding reports the first argument of cmd that names a
// control file, unless the program only reads its operands.
func commandControlFinding(cmd SimpleCommand, in Input, opts Options) (Finding, bool) {
	if len(cmd.Argv) == 0 {
		return Finding{}, false
	}
	if cmd.Original == "" && cmd.Program == "" && readOnlyPrograms[cmd.Argv[0]] {
		return Finding{}, false
	}
	cwds := cmd.Cwds
	if len(cwds) == 0 {
		cwds = []string{cmd.Cwd}
	}
	for _, tok := range cmd.Argv[1:] {
		for _, value := range controlCandidates(tok) {
			for _, cwd := range cwds {
				if f, ok := controlFinding(value, cwd, "argument", false, in, opts); ok {
					return f, true
				}
			}
		}
	}
	return Finding{}, false
}

// controlCandidates lists the names an argv token may refer to. Unlike
// pathCandidates it keeps bare names: `settings.json` names a control file
// when the command runs in `.claude`.
func controlCandidates(tok string) []string {
	var value string
	switch {
	case tok == "":
		return nil
	case strings.HasPrefix(tok, "--"):
		idx := strings.Index(tok, "=")
		if idx < 0 {
			return nil
		}
		value = tok[idx+1:]
	case strings.HasPrefix(tok, "-") && len(tok) > 1:
		if len(tok) <= 2 {
			return nil
		}
		value = tok[2:]
	default:
		value = tok
	}
	out := []string{value}
	if strings.ContainsAny(value, ",=") {
		for _, piece := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '=' }) {
			if piece != value {
				out = append(out, piece)
			}
		}
	}
	return out
}

// controlMatch resolves raw like classifyPath and returns the control path
// it names, preferring an audit log, with the resolved spelling that
// matched.
func (o Options) controlMatch(raw, cmdCwd string, in Input) (controlPath, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return controlPath{}, "", false
	}
	cs := o.controls
	if cs == nil {
		cs = newControlSet(o)
	}
	base, ok := commandBase(cmdCwd, in, o)
	if !ok {
		return controlPath{}, "", false
	}
	expanded, ok := expandHome(raw, o)
	if !ok {
		return controlPath{}, "", false
	}
	abs, lexical, physical := resolveViews(base, expanded)
	var best controlPath
	var bestView string
	found := false
	for _, view := range []string{abs, lexical, physical} {
		if c, ok := cs.match(view); ok && (!found || (c.kind == controlAudit && best.kind != controlAudit)) {
			best, bestView, found = c, view, true
		}
	}
	return best, bestView, found
}

// match returns the control path that target names. A target that still
// carries shell glob characters is matched as the pattern the shell would
// expand.
func (cs *controlSet) match(target string) (controlPath, bool) {
	glob := strings.ContainsAny(target, "*?[")
	var best controlPath
	found := false
	for _, c := range cs.paths {
		for _, form := range c.forms {
			hit := false
			if glob {
				hit = globNamesPath(target, form, c.tree)
			} else {
				hit = samePath(target, form) || (c.tree && underPath(target, form))
			}
			if hit && (!found || (c.kind == controlAudit && best.kind != controlAudit)) {
				best, found = c, true
			}
		}
	}
	return best, found
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.ToSlash(a), filepath.ToSlash(b))
}

// underPath reports whether target is strictly below dir.
func underPath(target, dir string) bool {
	t := strings.ToLower(filepath.ToSlash(target))
	d := strings.TrimSuffix(strings.ToLower(filepath.ToSlash(dir)), "/")
	return strings.HasPrefix(t, d+"/")
}

// globNamesPath reports whether the shell pattern could expand to name, or
// for a tree to name or anything below it. Components are matched one by
// one because a glob never crosses a separator.
func globNamesPath(pattern, name string, tree bool) bool {
	pc := strings.Split(strings.ToLower(filepath.ToSlash(pattern)), "/")
	nc := strings.Split(strings.ToLower(filepath.ToSlash(name)), "/")
	if tree {
		if len(pc) < len(nc) {
			return false
		}
		pc = pc[:len(nc)]
	} else if len(pc) != len(nc) {
		return false
	}
	for i := range pc {
		if !globComponent(pc[i], nc[i]) {
			return false
		}
	}
	return true
}

// globComponent matches one path component the way bash does by default:
// a leading dot must be matched literally, `[!...]` negates, and a
// malformed pattern stands for itself.
func globComponent(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return false
	}
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") {
		return false
	}
	ok, err := path.Match(strings.ReplaceAll(pattern, "[!", "[^"), name)
	return err == nil && ok
}
