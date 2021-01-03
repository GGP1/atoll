package atoll

// Generator is the interface that wraps the basic method Generate.
type Generator interface {
	Generate() (string, error)
}

// NewSecret generates a new secret.
func NewSecret(generator Generator) (string, error) {
	return generator.Generate()
}
