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

// getFuncName returns the name of the function passed.
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

// shuffle changes randomly the order of the password elements.
func shuffle(key []rune) string {
	for i := range key {
		j := randInt(i + 1)
		key[i], key[j] = key[j], key[i]
	}

	return string(key)
}
