package action

import (
	_ "embed"

	"github.com/safe-agentic-world/janus/internal/schema"
)

//go:embed schema/action.v1.json
var actionV1Schema []byte

func actionSchema() *schema.Schema {
	s, err := schema.ParseSchema(actionV1Schema)
	if err != nil {
		panic(err)
	}
	return s
}
