package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

// Upstream tool definition pinning modes.
const (
	// ToolPinModeOff disables definition pinning: the pin file is neither read nor written.
	ToolPinModeOff = "off"
	// ToolPinModeRecord pins a tool definition on first sight and denies later calls whose
	// live definition no longer matches the pin.
	ToolPinModeRecord = "record"
	// ToolPinModeStrict additionally denies calls to any tool that has no pin.
	ToolPinModeStrict = "strict"

	toolPinFileVersion = "v1"

	// Decision reason codes returned when the pin check refuses a forwarded call.
	denyByToolDefinitionChange   = "deny_by_tool_definition_change"
	denyByUnpinnedToolDefinition = "deny_by_unpinned_tool_definition"

	// toolPinStoreError is the stable downstream error code when the pin file cannot be
	// read or written at call time. The call fails closed.
	toolPinStoreError = "TOOL_PIN_STORE_ERROR"

	toolPinAuditEventType = "mcp.tool_definition_pin"

	toolPinResultPinned     = "PINNED"
	toolPinResultDenied     = "DENIED_TOOL_DEFINITION"
	toolPinResultStoreError = "TOOL_PIN_STORE_ERROR"
)

// UpstreamToolPinsConfig configures upstream tool definition pinning for the forwarded tool
// registry. An empty Mode means pinning is not configured and behaves like ToolPinModeOff;
// the operator-facing config layer defaults the mode to record and the file to
// upstream-tool-pins.json next to the config file.
type UpstreamToolPinsConfig struct {
	Mode string
	File string
}

func normalizeToolPinMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return ToolPinModeOff, nil
	case ToolPinModeOff:
		return ToolPinModeOff, nil
	case ToolPinModeRecord:
		return ToolPinModeRecord, nil
	case ToolPinModeStrict:
		return ToolPinModeStrict, nil
	default:
		return "", fmt.Errorf("invalid upstream tool pin mode %q: expected record|strict|off", strings.TrimSpace(mode))
	}
}

func normalizeUpstreamToolPinsConfig(cfg UpstreamToolPinsConfig) (UpstreamToolPinsConfig, error) {
	mode, err := normalizeToolPinMode(cfg.Mode)
	if err != nil {
		return UpstreamToolPinsConfig{}, err
	}
	file := strings.TrimSpace(cfg.File)
	if mode != ToolPinModeOff && file == "" {
		return UpstreamToolPinsConfig{}, fmt.Errorf("upstream tool pin file is required for mode %q", mode)
	}
	return UpstreamToolPinsConfig{Mode: mode, File: file}, nil
}

// ToolDefinitionPin is one pinned upstream tool definition as stored in the pin file.
type ToolDefinitionPin struct {
	DefinitionHash string `json:"definition_hash"`
	PinnedAt       string `json:"pinned_at"`
	Name           string `json:"name"`
	Description    string `json:"description"`
}

// ToolPinRecord is a pin together with the upstream server and tool it binds.
type ToolPinRecord struct {
	Server string
	Tool   string
	Pin    ToolDefinitionPin
}

type toolPinFile struct {
	Version string                       `json:"version"`
	Pins    map[string]ToolDefinitionPin `json:"pins"`
}

// ToolPinKey is the pin file key for an upstream tool: "<server>/<tool>".
func ToolPinKey(server, tool string) string {
	return strings.TrimSpace(server) + "/" + strings.TrimSpace(tool)
}

// ParseToolPinKey splits "<server>/<tool>" at the first slash.
func ParseToolPinKey(key string) (string, string, error) {
	trimmed := strings.TrimSpace(key)
	idx := strings.Index(trimmed, "/")
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", fmt.Errorf("invalid upstream tool pin key %q: expected <server>/<tool>", trimmed)
	}
	server := strings.TrimSpace(trimmed[:idx])
	tool := strings.TrimSpace(trimmed[idx+1:])
	if server == "" || tool == "" {
		return "", "", fmt.Errorf("invalid upstream tool pin key %q: expected <server>/<tool>", trimmed)
	}
	return server, tool, nil
}

// ToolDefinitionHash is the hex SHA-256 over the canonical JSON of
// {"name": ..., "description": ..., "inputSchema": ...}; inputSchema is omitted when the
// upstream advertised none. Key order and whitespace of the upstream payload do not change
// the hash; any change to the description or the schema does.
func ToolDefinitionHash(name, description string, inputSchema map[string]any) (string, error) {
	definition := map[string]any{
		"name":        name,
		"description": description,
	}
	if len(inputSchema) > 0 {
		definition["inputSchema"] = inputSchema
	}
	encoded, err := json.Marshal(definition)
	if err != nil {
		return "", fmt.Errorf("encode tool definition: %w", err)
	}
	canonical, err := canonicaljson.Canonicalize(encoded)
	if err != nil {
		return "", fmt.Errorf("canonicalize tool definition: %w", err)
	}
	return canonicaljson.HashSHA256(canonical), nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validateToolPin(pin ToolDefinitionPin) error {
	if !isSHA256Hex(pin.DefinitionHash) {
		return errors.New("definition_hash must be a lowercase hex sha256")
	}
	if pinnedAt := strings.TrimSpace(pin.PinnedAt); pinnedAt != "" {
		if _, err := time.Parse(time.RFC3339, pinnedAt); err != nil {
			return errors.New("pinned_at must be an RFC3339 timestamp")
		}
	}
	return nil
}

func parseToolPinFile(data []byte) (map[string]ToolDefinitionPin, error) {
	var file toolPinFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("trailing data after pin document")
	}
	if file.Version != toolPinFileVersion {
		return nil, fmt.Errorf("unsupported version %q: expected %q", file.Version, toolPinFileVersion)
	}
	pins := make(map[string]ToolDefinitionPin, len(file.Pins))
	for key, pin := range file.Pins {
		server, tool, err := ParseToolPinKey(key)
		if err != nil {
			return nil, err
		}
		if err := validateToolPin(pin); err != nil {
			return nil, fmt.Errorf("pin %q: %w", key, err)
		}
		normalized := ToolPinKey(server, tool)
		if _, exists := pins[normalized]; exists {
			return nil, fmt.Errorf("duplicate pin key %q", normalized)
		}
		pins[normalized] = pin
	}
	return pins, nil
}

func readToolPinFile(path string) (map[string]ToolDefinitionPin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read upstream tool pin file %s: %w", path, err)
	}
	pins, err := parseToolPinFile(data)
	if err != nil {
		return nil, fmt.Errorf("parse upstream tool pin file %s: %w", path, err)
	}
	return pins, nil
}

func writeToolPinFileAtomic(path string, pins map[string]ToolDefinitionPin) error {
	if pins == nil {
		pins = map[string]ToolDefinitionPin{}
	}
	data, err := json.MarshalIndent(toolPinFile{Version: toolPinFileVersion, Pins: pins}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode upstream tool pin file: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write upstream tool pin file %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	discard := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write upstream tool pin file %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return discard(err)
	}
	if err := tmp.Sync(); err != nil {
		return discard(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return discard(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write upstream tool pin file %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write upstream tool pin file %s: %w", path, err)
	}
	return nil
}

// ToolPinStore is the sidecar pin file that binds each upstream tool ("<server>/<tool>") to
// the hash of the definition an operator has accepted. The file is the source of truth:
// every lookup re-reads it when it changed on disk, so a pin accepted or removed with
// `nomos mcp pins` takes effect without restarting the gateway, and every write is a
// read-merge-write through an atomic temp-file rename.
type ToolPinStore struct {
	path string
	mode string
	now  func() time.Time

	mu     sync.Mutex
	pins   map[string]ToolDefinitionPin
	loaded bool
	exists bool
	// info is the stat of the file the in-memory pins were loaded from. Writers replace the
	// file through an atomic rename, so os.SameFile detects a rewrite even when the size and
	// modification time did not change.
	info os.FileInfo
}

// OpenToolPinStore loads the pin file at path. A missing file yields an empty store; a file
// that cannot be read or parsed is an error so callers fail closed.
func OpenToolPinStore(path, mode string) (*ToolPinStore, error) {
	normalizedMode, err := normalizeToolPinMode(mode)
	if err != nil {
		return nil, err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("upstream tool pin file path is required")
	}
	store := &ToolPinStore{
		path: path,
		mode: normalizedMode,
		now:  time.Now,
		pins: map[string]ToolDefinitionPin{},
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.refreshLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

// openToolPinStoreForRuntime opens the store the gateway enforces with. Mode off returns a
// nil store and never touches the file.
func openToolPinStoreForRuntime(cfg UpstreamToolPinsConfig) (*ToolPinStore, error) {
	normalized, err := normalizeUpstreamToolPinsConfig(cfg)
	if err != nil {
		return nil, err
	}
	if normalized.Mode == ToolPinModeOff {
		return nil, nil
	}
	return OpenToolPinStore(normalized.File, normalized.Mode)
}

// Mode returns the enforcement mode the store was opened with.
func (s *ToolPinStore) Mode() string {
	if s == nil {
		return ToolPinModeOff
	}
	return s.mode
}

// Path returns the pin file path.
func (s *ToolPinStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *ToolPinStore) refreshLocked() error {
	info, err := os.Stat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if s.loaded && !s.exists {
				return nil
			}
			s.pins = map[string]ToolDefinitionPin{}
			s.loaded = true
			s.exists = false
			s.info = nil
			return nil
		}
		return fmt.Errorf("stat upstream tool pin file %s: %w", s.path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("upstream tool pin file %s is a directory", s.path)
	}
	if s.loaded && s.exists && s.info != nil && os.SameFile(s.info, info) && info.ModTime().Equal(s.info.ModTime()) && info.Size() == s.info.Size() {
		return nil
	}
	pins, err := readToolPinFile(s.path)
	if err != nil {
		return err
	}
	s.pins = pins
	s.loaded = true
	s.exists = true
	s.info = info
	return nil
}

func (s *ToolPinStore) persistLocked(pins map[string]ToolDefinitionPin) error {
	if err := writeToolPinFileAtomic(s.path, pins); err != nil {
		return err
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("stat upstream tool pin file %s: %w", s.path, err)
	}
	s.pins = pins
	s.loaded = true
	s.exists = true
	s.info = info
	return nil
}

func clonePins(in map[string]ToolDefinitionPin) map[string]ToolDefinitionPin {
	out := make(map[string]ToolDefinitionPin, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (s *ToolPinStore) newPin(tool, definitionHash, description string) ToolDefinitionPin {
	return ToolDefinitionPin{
		DefinitionHash: definitionHash,
		PinnedAt:       s.now().UTC().Format(time.RFC3339),
		Name:           strings.TrimSpace(tool),
		Description:    description,
	}
}

// Lookup returns the pin bound to server/tool. The error is non-nil when the pin file changed
// on disk and can no longer be read or parsed; callers must fail closed.
func (s *ToolPinStore) Lookup(server, tool string) (ToolDefinitionPin, bool, error) {
	if s == nil {
		return ToolDefinitionPin{}, false, errors.New("upstream tool pin store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return ToolDefinitionPin{}, false, err
	}
	pin, ok := s.pins[ToolPinKey(server, tool)]
	return pin, ok, nil
}

// PinIfAbsent records the definition when no pin exists yet and reports whether it created
// one. An existing pin is returned unchanged, even when its hash differs. Nothing is kept in
// memory unless the file write succeeded.
func (s *ToolPinStore) PinIfAbsent(server, tool, definitionHash, description string) (ToolDefinitionPin, bool, error) {
	if s == nil {
		return ToolDefinitionPin{}, false, errors.New("upstream tool pin store is not configured")
	}
	if !isSHA256Hex(definitionHash) {
		return ToolDefinitionPin{}, false, errors.New("tool definition hash is not a lowercase hex sha256")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return ToolDefinitionPin{}, false, err
	}
	key := ToolPinKey(server, tool)
	if existing, ok := s.pins[key]; ok {
		return existing, false, nil
	}
	pin := s.newPin(tool, definitionHash, description)
	next := clonePins(s.pins)
	next[key] = pin
	if err := s.persistLocked(next); err != nil {
		return ToolDefinitionPin{}, false, err
	}
	return pin, true, nil
}

// Pin records or replaces the pin bound to server/tool and returns the previous pin, if any.
func (s *ToolPinStore) Pin(server, tool, definitionHash, description string) (ToolDefinitionPin, *ToolDefinitionPin, error) {
	if s == nil {
		return ToolDefinitionPin{}, nil, errors.New("upstream tool pin store is not configured")
	}
	if !isSHA256Hex(definitionHash) {
		return ToolDefinitionPin{}, nil, errors.New("tool definition hash is not a lowercase hex sha256")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return ToolDefinitionPin{}, nil, err
	}
	key := ToolPinKey(server, tool)
	var previous *ToolDefinitionPin
	if existing, ok := s.pins[key]; ok {
		copied := existing
		previous = &copied
	}
	pin := s.newPin(tool, definitionHash, description)
	next := clonePins(s.pins)
	next[key] = pin
	if err := s.persistLocked(next); err != nil {
		return ToolDefinitionPin{}, nil, err
	}
	return pin, previous, nil
}

// Remove deletes the pin bound to server/tool and reports whether one existed.
func (s *ToolPinStore) Remove(server, tool string) (bool, error) {
	if s == nil {
		return false, errors.New("upstream tool pin store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return false, err
	}
	key := ToolPinKey(server, tool)
	if _, ok := s.pins[key]; !ok {
		return false, nil
	}
	next := clonePins(s.pins)
	delete(next, key)
	if err := s.persistLocked(next); err != nil {
		return false, err
	}
	return true, nil
}

// List returns every pin sorted by key.
func (s *ToolPinStore) List() ([]ToolPinRecord, error) {
	if s == nil {
		return nil, errors.New("upstream tool pin store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(s.pins))
	for key := range s.pins {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ToolPinRecord, 0, len(keys))
	for _, key := range keys {
		server, tool, err := ParseToolPinKey(key)
		if err != nil {
			return nil, err
		}
		out = append(out, ToolPinRecord{Server: server, Tool: tool, Pin: s.pins[key]})
	}
	return out, nil
}

// UpstreamToolDefinition is the pin-relevant view of a live upstream tool.
type UpstreamToolDefinition struct {
	Server         string `json:"server"`
	Tool           string `json:"tool"`
	Description    string `json:"description"`
	DefinitionHash string `json:"definition_hash"`
	HasInputSchema bool   `json:"has_input_schema"`
}

// EnumerateUpstreamToolDefinitions starts the named upstream server from options with the
// same session code the gateway uses, lists its tools, closes the session, and returns the
// definitions with their hashes. Pins are not consulted or written.
func EnumerateUpstreamToolDefinitions(options RuntimeOptions, serverName string, id identity.VerifiedIdentity, recorder audit.Recorder) ([]UpstreamToolDefinition, error) {
	parsed, err := ParseRuntimeOptions(options)
	if err != nil {
		return nil, err
	}
	serverName = strings.TrimSpace(serverName)
	var config *UpstreamServerConfig
	for idx := range parsed.UpstreamServers {
		if strings.TrimSpace(parsed.UpstreamServers[idx].Name) == serverName {
			config = &parsed.UpstreamServers[idx]
			break
		}
	}
	if config == nil {
		return nil, fmt.Errorf("upstream mcp server %q is not configured", serverName)
	}
	logger, err := newRuntimeLogger(parsed)
	if err != nil {
		return nil, err
	}
	if recorder == nil {
		recorder = noopRecorder{}
	}
	supervisor, err := newUpstreamSupervisor([]UpstreamServerConfig{*config}, logger, parsed.Telemetry, id, parsed.CredentialBroker, recorder, nil)
	if err != nil {
		return nil, err
	}
	defer supervisor.close()
	tools := supervisor.snapshotTools()
	out := make([]UpstreamToolDefinition, 0, len(tools))
	for _, tool := range tools {
		out = append(out, UpstreamToolDefinition{
			Server:         tool.ServerName,
			Tool:           tool.ToolName,
			Description:    tool.Description,
			DefinitionHash: tool.DefinitionHash,
			HasInputSchema: len(tool.InputSchema) > 0,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out, nil
}
