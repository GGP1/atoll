package atoll

import (
	"math"
	"strings"
	"testing"
)

func TestNewPassword(t *testing.T) {
	password, err := NewPassword(10, []int{2, 4}, "", "", true)
	if err != nil {
		t.Errorf("Failed generating the password: %v", err)
	}

	t.Log(password)
}

func TestGeneratePassword(t *testing.T) {
	passwords := []Password{
		{Length: 14, Format: []int{1, 5}, Include: "kure", Exclude: "ad", Repeat: false},
		{Length: 8, Format: []int{1, 4}, Include: "", Repeat: true},
		{Length: 40, Format: []int{1, 2, 3}, Include: "231", Repeat: false},
	}

	for _, p := range passwords {
		err := p.Generate()
		if err != nil {
			t.Errorf("Failed generating the password: %v", err)
		}

		if len(p.Secret) != int(p.Length) {
			t.Errorf("Wrong password length, expected %d characters, got %d", p.Length, len(p.Secret))
		}

		if p.Include != "" && !strings.ContainsAny(p.Secret, p.Include) {
			t.Error("Include chars weren't added to the password")
		}

		if p.Exclude != "" && strings.ContainsAny(p.Secret, p.Exclude) {
			t.Error("Password contains unwanted characters")
		}

		if !p.Repeat && p.Include == "" {
			uniques := make(map[rune]struct{}, p.Length)

			for _, char := range p.Secret {
				if _, c := uniques[char]; !c {
					uniques[char] = struct{}{}
				}
			}

			if len(p.Secret) != len(uniques) {
				diff := len(p.Secret) - len(uniques)
				t.Errorf("Did not expect duplicated characters, got: %d", diff)
			}
		}

		entropy := p.Entropy

		pool := poolLength(p.Include, p.Exclude, p.Format)
		pow := math.Pow(float64(pool), float64(p.Length))
		expected := math.Log2(pow)

		if math.Floor(entropy) != math.Floor(expected) {
			t.Errorf("Calculate entropy failed, expected: %f, got: %f", expected, entropy)
		}
	}
}

// poolLength returns the length of the pool used.
// This is used for testing purposes only.
func poolLength(include, exclude string, format []int) int {
	var poolLen int

	for _, level := range format {
		switch level {
		case 1:
			poolLen += len(lowerCase)
		case 2:
			poolLen += len(upperCase)
		case 3:
			poolLen += len(digit)
		case 4:
			poolLen += len(space)
		case 5:
			poolLen += len(special)
		}
	}

	poolLen += len(include)
	poolLen -= len(exclude)

	return poolLen
}
