package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/mcp"
)

// runMCPPins implements `nomos mcp pins <list|accept|remove>`, the operator flow for the
// upstream tool definition pin file configured under upstream.tool_pins.
func runMCPPins(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		writeHelpText(os.Stderr, mcpPinsHelpText())
		if len(args) == 0 {
			os.Exit(2)
		}
		return
	}
	switch args[0] {
	case "list":
		if err := executeMCPPinsList(args[1:], os.Stdout, os.Getenv); err != nil {
			cliFatalf("mcp pins list: %v", err)
		}
	case "accept":
		if err := executeMCPPinsAccept(args[1:], os.Stdout, os.Getenv); err != nil {
			cliFatalf("mcp pins accept: %v", err)
		}
	case "remove":
		if err := executeMCPPinsRemove(args[1:], os.Stdout, os.Getenv); err != nil {
			cliFatalf("mcp pins remove: %v", err)
		}
	default:
		cliFatal("mcp pins command required: list|accept|remove")
	}
}

type mcpPinsArgs struct {
	configPath   string
	policyBundle string
	format       string
	hash         string
	key          string
}

func parseMCPPinsArgs(args []string, allowKey, allowHash bool) (mcpPinsArgs, error) {
	parsed := mcpPinsArgs{format: "text"}
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		value := func() (string, error) {
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			return strings.TrimSpace(args[i]), nil
		}
		switch arg {
		case "-c", "--config":
			v, err := value()
			if err != nil {
				return mcpPinsArgs{}, err
			}
			parsed.configPath = v
		case "-p", "--policy-bundle":
			v, err := value()
			if err != nil {
				return mcpPinsArgs{}, err
			}
			parsed.policyBundle = v
		case "--format":
			v, err := value()
			if err != nil {
				return mcpPinsArgs{}, err
			}
			parsed.format = v
		case "--hash":
			if !allowHash {
				return mcpPinsArgs{}, fmt.Errorf("unknown flag %q", arg)
			}
			v, err := value()
			if err != nil {
				return mcpPinsArgs{}, err
			}
			parsed.hash = v
		default:
			if strings.HasPrefix(arg, "-") {
				return mcpPinsArgs{}, fmt.Errorf("unknown flag %q", arg)
			}
			if !allowKey {
				return mcpPinsArgs{}, fmt.Errorf("unexpected argument %q", arg)
			}
			if parsed.key != "" {
				return mcpPinsArgs{}, errors.New("only one <server>/<tool> is allowed")
			}
			parsed.key = arg
		}
	}
	switch strings.ToLower(strings.TrimSpace(parsed.format)) {
	case "", "text":
		parsed.format = "text"
	case "json":
		parsed.format = "json"
	default:
		return mcpPinsArgs{}, errors.New("--format must be text or json")
	}
	return parsed, nil
}

type mcpPinsContext struct {
	cfg   gateway.Config
	store *mcp.ToolPinStore
}

func openMCPPinsContext(parsed mcpPinsArgs, getenv func(string) string) (mcpPinsContext, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	resolved, err := resolveMCPInvocation(parsed.configPath, parsed.policyBundle, "", false, getenv)
	if err != nil {
		return mcpPinsContext{}, err
	}
	cfg, err := gateway.LoadConfig(resolved.ConfigPath, getenv, resolved.PolicyBundle)
	if err != nil {
		return mcpPinsContext{}, fmt.Errorf("load config: %w", err)
	}
	store, err := mcp.OpenToolPinStore(cfg.Upstream.ToolPins.File, cfg.Upstream.ToolPins.Mode)
	if err != nil {
		return mcpPinsContext{}, err
	}
	return mcpPinsContext{cfg: cfg, store: store}, nil
}

type mcpPinRecord struct {
	Key            string `json:"key"`
	Server         string `json:"server"`
	Tool           string `json:"tool"`
	DefinitionHash string `json:"definition_hash"`
	PinnedAt       string `json:"pinned_at,omitempty"`
	Description    string `json:"description,omitempty"`
}

type mcpPinsListOutput struct {
	File string         `json:"file"`
	Mode string         `json:"mode"`
	Pins []mcpPinRecord `json:"pins"`
}

func executeMCPPinsList(args []string, stdout io.Writer, getenv func(string) string) error {
	parsed, err := parseMCPPinsArgs(args, false, false)
	if err != nil {
		return err
	}
	pins, err := openMCPPinsContext(parsed, getenv)
	if err != nil {
		return err
	}
	records, err := pins.store.List()
	if err != nil {
		return err
	}
	out := mcpPinsListOutput{
		File: pins.store.Path(),
		Mode: pins.store.Mode(),
		Pins: make([]mcpPinRecord, 0, len(records)),
	}
	for _, record := range records {
		out.Pins = append(out.Pins, mcpPinRecord{
			Key:            mcp.ToolPinKey(record.Server, record.Tool),
			Server:         record.Server,
			Tool:           record.Tool,
			DefinitionHash: record.Pin.DefinitionHash,
			PinnedAt:       record.Pin.PinnedAt,
			Description:    record.Pin.Description,
		})
	}
	if parsed.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if _, err := fmt.Fprintf(stdout, "file=%s mode=%s pins=%d\n", out.File, out.Mode, len(out.Pins)); err != nil {
		return err
	}
	for _, pin := range out.Pins {
		if _, err := fmt.Fprintf(stdout, "%s %s pinned_at=%s\n", pin.Key, pin.DefinitionHash, pin.PinnedAt); err != nil {
			return err
		}
	}
	return nil
}

type mcpPinAcceptOutput struct {
	Key                    string `json:"key"`
	Server                 string `json:"server"`
	Tool                   string `json:"tool"`
	PreviousDefinitionHash string `json:"previous_definition_hash,omitempty"`
	DefinitionHash         string `json:"definition_hash"`
	PinnedAt               string `json:"pinned_at"`
	Description            string `json:"description,omitempty"`
	Source                 string `json:"source"`
	Changed                bool   `json:"changed"`
	File                   string `json:"file"`
}

// executeMCPPinsAccept rewrites the pin for <server>/<tool> to the definition the upstream
// advertises right now, enumerated over the same upstream session code the gateway uses.
// With --hash the reviewed hash is pinned instead and no upstream connection is made.
func executeMCPPinsAccept(args []string, stdout io.Writer, getenv func(string) string) error {
	parsed, err := parseMCPPinsArgs(args, true, true)
	if err != nil {
		return err
	}
	if parsed.key == "" {
		return errors.New("<server>/<tool> is required")
	}
	server, tool, err := mcp.ParseToolPinKey(parsed.key)
	if err != nil {
		return err
	}
	pins, err := openMCPPinsContext(parsed, getenv)
	if err != nil {
		return err
	}
	var (
		definitionHash string
		description    string
		source         string
	)
	if strings.TrimSpace(parsed.hash) != "" {
		source = "hash"
		definitionHash = strings.ToLower(strings.TrimSpace(parsed.hash))
		if previous, ok, err := pins.store.Lookup(server, tool); err != nil {
			return err
		} else if ok {
			description = previous.Description
		}
	} else {
		source = "upstream"
		live, err := enumerateLiveToolDefinition(pins.cfg, server, tool)
		if err != nil {
			return err
		}
		definitionHash = live.DefinitionHash
		description = live.Description
	}
	pin, previous, err := pins.store.Pin(server, tool, definitionHash, description)
	if err != nil {
		return err
	}
	out := mcpPinAcceptOutput{
		Key:            mcp.ToolPinKey(server, tool),
		Server:         server,
		Tool:           tool,
		DefinitionHash: pin.DefinitionHash,
		PinnedAt:       pin.PinnedAt,
		Description:    pin.Description,
		Source:         source,
		Changed:        previous == nil || previous.DefinitionHash != pin.DefinitionHash,
		File:           pins.store.Path(),
	}
	if previous != nil {
		out.PreviousDefinitionHash = previous.DefinitionHash
	}
	if parsed.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	previousLabel := "none"
	if out.PreviousDefinitionHash != "" {
		previousLabel = out.PreviousDefinitionHash
	}
	_, err = fmt.Fprintf(stdout, "accepted %s previous=%s new=%s source=%s changed=%t file=%s\n", out.Key, previousLabel, out.DefinitionHash, out.Source, out.Changed, out.File)
	return err
}

func enumerateLiveToolDefinition(cfg gateway.Config, server, tool string) (mcp.UpstreamToolDefinition, error) {
	credentialBroker, err := gateway.BuildCredentialBroker(cfg, time.Now)
	if err != nil {
		return mcp.UpstreamToolDefinition{}, fmt.Errorf("init credential broker: %w", err)
	}
	runtimeOptions, err := buildMCPRuntimeOptions(cfg, credentialBroker, "warn", "text", mcp.ToolSurfaceCanonical, false)
	if err != nil {
		return mcp.UpstreamToolDefinition{}, fmt.Errorf("invalid mcp runtime options: %w", err)
	}
	recorder, err := buildProtocolSafeMCPRecorder(cfg)
	if err != nil {
		return mcp.UpstreamToolDefinition{}, fmt.Errorf("init mcp audit recorder: %w", err)
	}
	if closer, ok := recorder.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}
	id := identity.VerifiedIdentity{
		Principal:   cfg.Identity.Principal,
		Agent:       cfg.Identity.Agent,
		Environment: cfg.Identity.Environment,
	}
	definitions, err := mcp.EnumerateUpstreamToolDefinitions(runtimeOptions, server, id, recorder)
	if err != nil {
		return mcp.UpstreamToolDefinition{}, err
	}
	for _, definition := range definitions {
		if definition.Tool == tool {
			return definition, nil
		}
	}
	return mcp.UpstreamToolDefinition{}, fmt.Errorf("upstream mcp server %q does not advertise tool %q", server, tool)
}

type mcpPinRemoveOutput struct {
	Key     string `json:"key"`
	Server  string `json:"server"`
	Tool    string `json:"tool"`
	Removed bool   `json:"removed"`
	File    string `json:"file"`
}

func executeMCPPinsRemove(args []string, stdout io.Writer, getenv func(string) string) error {
	parsed, err := parseMCPPinsArgs(args, true, false)
	if err != nil {
		return err
	}
	if parsed.key == "" {
		return errors.New("<server>/<tool> is required")
	}
	server, tool, err := mcp.ParseToolPinKey(parsed.key)
	if err != nil {
		return err
	}
	pins, err := openMCPPinsContext(parsed, getenv)
	if err != nil {
		return err
	}
	removed, err := pins.store.Remove(server, tool)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("no pin recorded for %q in %s", mcp.ToolPinKey(server, tool), pins.store.Path())
	}
	out := mcpPinRemoveOutput{
		Key:     mcp.ToolPinKey(server, tool),
		Server:  server,
		Tool:    tool,
		Removed: true,
		File:    pins.store.Path(),
	}
	if parsed.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	_, err = fmt.Fprintf(stdout, "removed %s file=%s\n", out.Key, out.File)
	return err
}
