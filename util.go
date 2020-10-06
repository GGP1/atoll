package atoll

import (
	"crypto/rand"
	"math"
	"math/big"
	"reflect"
	"runtime"
	"strings"
)

const commonPatterns string = `(?i)abc|123|1111|qwerty|asdf|zxcv|
1qaz|zaq1|qazwsx|pass|login|admin|master`

// calculateEntropy returns the secret security information.
func calculateEntropy(poolLength, secretLength int) float64 {
	// log2(poolLength^secretLength)
	pow := math.Pow(float64(poolLength), float64(secretLength))
	entropy := math.Log2(pow)

	// Make sure to return +Inf instead of -Inf, which happens
	// when a number is larger than 64 bits
	if math.IsInf(entropy, -1) {
		entropy = math.Inf(0)
	}

	return entropy
}

// getFuncName returns the name of the function.
func getFuncName(f list) string {
	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	name := strings.Split(fn, ".")
	return name[2]
}

// randInt returns a cryptographically secure random integer in [0, max).
//
// Error handling is skipped as we are not using zero nor negative numbers.
func randInt(max int) int {
	randN, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))

	return int(randN.Int64())
}

// removeElem deletes an element from the slice passed.
func removeElem(slicePtr *[]rune, elem int) {
	slice := *slicePtr
	*slicePtr = append(slice[:elem], slice[elem+1:]...)
}
