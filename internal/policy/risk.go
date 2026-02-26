package policy

import "github.com/ai-developer-project/janus/internal/normalize"

type RiskFlags map[string]bool

func ComputeRiskFlags(action normalize.NormalizedAction) RiskFlags {
	flags := RiskFlags{}
	switch action.ActionType {
	case "process.exec":
		flags["risk.exec"] = true
	case "net.http_request":
		flags["risk.net"] = true
	case "fs.write", "repo.apply_patch":
		flags["risk.write"] = true
	case "secrets.checkout":
		flags["risk.secrets"] = true
	}
	if len(action.Params) >= 32*1024 {
		flags["risk.large_io"] = true
	}
	if action.TraceActionCount >= 100 {
		flags["risk.high_fanout"] = true
	}
	return flags
}
