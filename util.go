package atoll

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

var commonPatterns = regexp.MustCompile(`(?i)abc|123|qwerty|asdf|zxcv|1qaz|
zaq1|qazwsx|pass|login|admin|master|!@#$|!234|!Q@W`)

// getFuncName returns the name of the function passed, an empty string if it's nil.
func getFuncName(f list) string {
	if f == nil {
		return ""
	}

	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer())
	if fn == nil {
		return ""
	}

	name := fn.Name()
	lastDot := strings.LastIndexByte(name, '.')
	return name[lastDot+1:]
}

// randInt returns a cryptographically secure random integer in [0, max).
func randInt(max int) (int64, error) {
	if max <= 0 {
		return 0, errors.New("no characters available to choose from")
	}

	randN, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("reading random number: %w", err)
	}

	return randN.Int64(), nil
}

// shuffle changes randomly the order of the key elements.
func shuffle(key []byte) ([]byte, error) {
	for i := range key {
		j, err := randInt(i + 1)
		if err != nil {
			return nil, err
		}

		key[i], key[j] = key[j], key[i]
	}

	return key, nil
}
