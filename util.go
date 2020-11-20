package atoll

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"runtime"
	"strings"
)

const commonPatterns string = `(?i)abc|123|qwerty|asdf|zxcv|1qaz|
zaq1|qazwsx|pass|login|admin|master`

// getFuncName returns the name of the function.
func getFuncName(f list) string {
	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	name := strings.Split(fn, ".")
	return name[len(name)-1]
}

// randInt returns a cryptographically secure random integer in [0, max).
//
// The error is skipped as we are using numbers > 0.
func randInt(max int) int {
	randN, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))

	return int(randN.Int64())
}

// removeElem deletes an element from the slicePtr.
func removeElem(slicePtr *[]rune, elem int) {
	slice := *slicePtr
	*slicePtr = append(slice[:elem], slice[elem+1:]...)
}

// Shuffle randomizes the order of the password elements.
func shuffle(password []rune) {
	for i := range password {
		j := randInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}
}
