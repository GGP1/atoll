package atoll

// Secret is the interface that wraps the basic method Generate.
type Secret interface {
	Generate() error
}

// NewSecret generates a new secret.
func NewSecret(secret Secret) error {
	return secret.Generate()
}
