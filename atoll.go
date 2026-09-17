// Package atoll is a secret generator that makes use of the crypto/rand package to generate
// cryptographically secure numbers and offer a high level of randomness.
package atoll

import (
	"math"
	"strings"
)

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

// Keyspace returns the set of all possible permutations of the generated key (2 ^ entropy).
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

// SecretFromString returns a secret with the same parameters that were used for the provided string.
//
// Given the complexity to determine if the secret is a passphrase when separators are a custom set
// of characters, it will always be of type Password.
//
// The secret returned is an approximation used to estimate the strength of the string: it assumes
// that every character was randomly chosen from the levels detected. Strings that weren't generated
// that way (a passphrase or a secret picked by a human, for instance) will have their entropy
// overestimated.
func SecretFromString(str string) Secret {
	if len(str) == 0 {
		return &Password{}
	}

	allLevels := []Level{Lower, Upper, Digit, Space, Special}
	levels := make([]Level, 0, len(allLevels))
	for _, lvl := range allLevels {
		if strings.ContainsAny(string(lvl), str) {
			levels = append(levels, lvl)
		}
	}

	// If the password was composed of characters that are not part of the pre-defined levels,
	// use all of them by default
	if len(levels) == 0 {
		levels = allLevels
	}

	characters := make(map[rune]struct{}, len(str))
	repeat := false
	for _, r := range str {
		if _, ok := characters[r]; ok {
			repeat = true
			break
		}
		characters[r] = struct{}{}
	}

	return &Password{
		Repeat: repeat,
		Levels: levels,
		Length: uint64(len(str)),
	}
}
