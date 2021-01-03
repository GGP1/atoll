package atoll

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"runtime"
	"strings"
)

const commonPatterns string = `(?i)abc|123|qwerty|asdf|zxcv|1qaz|
zaq1|qazwsx|pass|login|admin|master|!@#$|!234|!Q@W`

// getFuncName returns the name of the function.
func getFuncName(f list) string {
	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	name := strings.Split(fn, ".")
	return name[len(name)-1]
}

// randInt returns a cryptographically secure random integer in [0, max).
func randInt(max int) int {
	// The error is skipped as max is always len(something).
	randN, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))

	return int(randN.Int64())
}

// randInsert inserts the given char in a random position.
func randInsert(secret, char string) string {
	i := randInt(len(secret) + 1)
	return secret[0:i] + char + secret[i:]
}

// Shuffle changes randomly the order of the password elements.
func shuffle(password []rune) string {
	for i := range password {
		j := randInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}
