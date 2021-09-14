package atoll

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

var commonPatterns *regexp.Regexp

func init() {
	commonPatterns = regexp.MustCompile(`(?i)abc|123|qwerty|asdf|zxcv|1qaz|
	zaq1|qazwsx|pass|login|admin|master|!@#$|!234|!Q@W`)
}

var pool = &sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

// getBuf returns a buffer from the pool.
func getBuf() *bytes.Buffer {
	return pool.Get().(*bytes.Buffer)
}

// putBuf resets buf and puts it back to the pool.
func putBuf(buf *bytes.Buffer) {
	buf.Reset()
	pool.Put(buf)
}

// getFuncName returns the name of the function passed.
func getFuncName(f list) string {
	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	lastDot := strings.LastIndexByte(fn, '.')
	return fn[lastDot+1:]
}

// randInt returns a cryptographically secure random integer in [0, max).
func randInt(max int) int64 {
	// The error is skipped as max is always > 0.
	randN, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))

	return randN.Int64()
}

// shuffle changes randomly the order of the password elements.
func shuffle(key []rune) string {
	for i := range key {
		j := randInt(i + 1)
		key[i], key[j] = key[j], key[i]
	}

	return string(key)
}
