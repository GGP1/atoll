package atoll

// Secret is the interface that wraps the basic method Generate.
type Secret interface {
	Generate() (string, error)
}

// NewSecret generates a new secret.
func NewSecret(secret Secret) (string, error) {
	return secret.Generate()
}
