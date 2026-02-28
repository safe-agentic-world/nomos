package gateway

import (
	"time"

	"github.com/safe-agentic-world/janus/internal/credentials"
)

func buildCredentialBroker(cfg Config, now func() time.Time) (*credentials.Broker, error) {
	if !cfg.Credentials.Enabled {
		return nil, nil
	}
	secrets := make([]credentials.Secret, 0, len(cfg.Credentials.Secrets))
	for _, s := range cfg.Credentials.Secrets {
		secrets = append(secrets, credentials.Secret{
			ID:         s.ID,
			EnvKey:     s.EnvKey,
			Value:      s.Value,
			TTLSeconds: s.TTLSeconds,
		})
	}
	return credentials.NewBroker(secrets, now)
}
