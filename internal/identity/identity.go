package identity

type VerifiedIdentity struct {
	Principal   string
	Agent       string
	Environment string
}

type AuthConfig struct {
	APIKeys        map[string]string
	ServiceSecrets map[string]string
	AgentSecrets   map[string]string
	Environment    string
}
