// Package atoll is a secret generator that makes use of the crypto/rand package to generate
// cryptographically secure numbers and offer a high level of randomness.
package atoll

import "math"

// 1 trillion is the number of guesses per second Edward Snowden said we should be prepared for.
const guessesPerSecond = 1000000000000

// Secret is the interface that wraps the basic methods Generate and Entropy.
type Secret interface {
	Generate() ([]byte, error)
	Entropy() float64
}

// NewSecret generates a new secret.
func NewSecret(secret Secret) ([]byte, error) {
	return secret.Generate()
}

// Keyspace returns the set of all possible permutations of the generated key (poolLength ^ keyLength).
//
// On average, half the key space must be searched to find the solution (keyspace/2).
func Keyspace(secret Secret) float64 {
	return math.Pow(2, secret.Entropy())
}

// SecondsToCrack returns the time taken in seconds by a brute force attack to crack the secret.
//
// It's assumed that the attacker can perform 1 trillion guesses per second.
func SecondsToCrack(secret Secret) float64 {
	return Keyspace(secret) / guessesPerSecond
}
