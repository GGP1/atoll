package atoll

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

var commonPatterns *regexp.Regexp

func init() {
	commonPatterns = regexp.MustCompile(`(?i)abc|123|qwerty|asdf|zxcv|1qaz|
	zaq1|qazwsx|pass|login|admin|master|!@#$|!234|!Q@W`)
}

// getFuncName returns the name of the function passed.
func getFuncName(f list) string {
	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	name := strings.Split(fn, ".")
	return name[len(name)-1]
}

// randInt returns a cryptographically secure random integer in [0, max).
func randInt(max int) int64 {
	// The error is skipped as max is always > 0.
	randN, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))

	return randN.Int64()
}

// removeChar returns pool without char, if it's not present it returns pool unchanged.
func removeChar(pool, char string) string {
	idx := strings.Index(pool, char)
	if idx == -1 {
		return pool
	}

	return pool[:idx] + pool[idx+1:]
}

// shuffle changes randomly the order of the password elements.
func shuffle(key []rune) string {
	for i := range key {
		j := randInt(i + 1)
		key[i], key[j] = key[j], key[i]
	}

	return string(key)
}
