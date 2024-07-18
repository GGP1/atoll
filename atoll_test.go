package atoll

import (
	"math"
	"testing"
)

func TestNewSecret(t *testing.T) {
	cases := []struct {
		secret Secret
		desc   string
	}{
		{
			desc: "Password",
			secret: &Password{
				Length:  15,
				Levels:  []Level{Lower, Upper, Digit, Space, Special},
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
		secret Secret
		desc   string
	}{
		{
			desc: "Password",
			secret: &Password{
				Length: 13,
				Levels: []Level{Lower, Upper, Digit},
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
		secret Secret
		desc   string
	}{
		{
			desc: "Password",
			secret: &Password{
				Length: 26,
				Levels: []Level{Lower, Upper},
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

func TestSecretFromString(t *testing.T) {
	cases := []struct {
		expected Secret
		str      string
	}{
		{
			str: "abc",
			expected: &Password{
				Length: 3,
				Levels: []Level{Lower},
				Repeat: false,
			},
		},
		{
			str: "aBc",
			expected: &Password{
				Length: 3,
				Levels: []Level{Lower, Upper},
				Repeat: false,
			},
		},
		{
			str: "aB1",
			expected: &Password{
				Length: 3,
				Levels: []Level{Lower, Upper, Digit},
				Repeat: false,
			},
		},
		{
			str: "aB1 _",
			expected: &Password{
				Length: 5,
				Levels: []Level{Lower, Upper, Digit, Space, Special},
				Repeat: false,
			},
		},
		{
			str: "aBa",
			expected: &Password{
				Length: 3,
				Levels: []Level{Lower, Upper},
				Repeat: true,
			},
		},
		{
			str: "KTPBv0y~e\\wj,kA]>!jgdG\"q",
			expected: &Password{
				Length: 24,
				Levels: []Level{Lower, Upper, Digit, Special},
				Repeat: true,
			},
		},
		{
			str: "世界",
			expected: &Password{
				Length: 6, // String contains multi-byte characters
				Levels: []Level{Lower, Upper, Digit, Space, Special},
				Repeat: false,
			},
		},
		{
			str: "परीक्षा",
			expected: &Password{
				Length: 21, // String contains multi-byte characters
				Levels: []Level{Lower, Upper, Digit, Space, Special},
				Repeat: false,
			},
		},
		{
			str:      "",
			expected: &Password{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.str, func(t *testing.T) {
			got := SecretFromString(tc.str)
			if got.Entropy() != tc.expected.Entropy() {
				t.Errorf("Expected %f, got %f", tc.expected.Entropy(), got.Entropy())
			}
		})
	}
}
