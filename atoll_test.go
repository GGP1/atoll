package atoll

import (
	"math"
	"testing"
)

func TestNewSecret(t *testing.T) {
	cases := []struct {
		desc   string
		secret Secret
	}{
		{
			desc: "Password",
			secret: &Password{
				Length:  15,
				Levels:  []Level{Lowercase, Uppercase, Digit, Space, Special},
				Include: "=",
				Exclude: "?",
				Repeat:  false,
			},
		},
		{
			desc: "Passphrase",
			secret: &Passphrase{
				Length:    6,
				Separator: "$",
				List:      NoList,
				Include:   []string{"secret"},
				Exclude:   []string{"test"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if _, err := NewSecret(tc.secret); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestKeyspace(t *testing.T) {
	cases := []struct {
		desc   string
		secret Secret
	}{
		{
			desc: "Password",
			secret: &Password{
				Length: 13,
				Levels: []Level{Lowercase, Uppercase, Digit},
			},
		},
		{
			desc: "Passphrase",
			secret: &Passphrase{
				Length: 7,
				List:   WordList,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			expected := math.Pow(2, tc.secret.Entropy())
			got := Keyspace(tc.secret)

			if got != expected {
				t.Errorf("Expected %f, got %f", expected, got)
			}
		})
	}
}

func TestSecondsToCrack(t *testing.T) {
	cases := []struct {
		desc   string
		secret Secret
	}{
		{
			desc: "Password",
			secret: &Password{
				Length: 26,
				Levels: []Level{Lowercase, Uppercase},
			},
		},
		{
			desc: "Passphrase",
			secret: &Passphrase{
				Length: 8,
				List:   SyllableList,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			expected := Keyspace(tc.secret) / guessesPerSecond
			got := SecondsToCrack(tc.secret)

			if got != expected {
				t.Errorf("Expected %f, got %f", expected, got)
			}
		})
	}
}
