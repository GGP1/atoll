package atoll

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"reflect"
	"runtime"
	"strings"
	"unicode"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

const commonPatterns string = `(?i)abc|123|qwerty|asdf|zxcv|1qaz|
zaq1|qazwsx|pass|login|admin|master`

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

// isMn returns if the rune is in the range of unicode.Mn (nonspacing marks).
func isMn(r rune) bool {
	return unicode.Is(unicode.Mn, r)
}

// Text normalization to NFKC
func normalize(str string) string {
	t := transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFKC)
	result, _, _ := transform.String(t, str)

	return result
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

// Shuffle pseudo-randomizes the order of elements.
// n is the number of elements. Shuffle panics if n < 0.
// swap swaps the elements with indexes i and j.
func shuffle(n int, swap func(i, j int)) error {
	if n < 0 {
		return errors.New("invalid argument to shuffle")
	}

	i := n - 1
	for ; i > 1<<31-1-1; i-- {
		j := randInt(i + 1)
		swap(i, j)
	}
	for ; i > 0; i-- {
		j := randInt(i + 1)
		swap(i, j)
	}

	return nil
}
