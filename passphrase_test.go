package atoll

import (
	"math"
	"strings"
	"testing"
)

func TestPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"No list": {
			Length:    14,
			Separator: "/",
			List:      NoList,
		},
		"Word list": {
			Length:    4,
			Separator: "",
			Include:   []string{"apple", "orange", "watermelon"},
			List:      WordList,
		},
		"Syllable list": {
			Length:    6,
			Separator: "==",
			Include:   []string{"test"},
			List:      SyllableList,
		},
		"Default values": {
			Length:  10,
			Include: []string{"background"},
			Exclude: []string{"unit"},
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			passphrase, err := tc.Generate()
			if err != nil {
				t.Fatalf("Generate() failed: %v", err)
			}

			words := strings.Split(passphrase, tc.Separator)
			if len(words) != int(tc.Length) {
				t.Errorf("Expected %d words, got %d", tc.Length, len(words))
			}

			if !strings.Contains(passphrase, tc.Separator) {
				t.Errorf("The separator %q is not used", tc.Separator)
			}

			for _, inc := range tc.Include {
				if !strings.Contains(passphrase, inc) {
					t.Errorf("Expected %q to be included", inc)
				}
			}

			for _, w := range words {
				for _, exc := range tc.Exclude {
					if exc == w {
						t.Errorf("Expected %q to be excluded", exc)
					}
				}
			}
		})
	}
}

func TestInvalidPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"invalid length":               {Length: 0},
		"invalid separator":            {Length: 5, Separator: "¿"},
		"len(Include) > Length":        {Length: 2, Include: []string{"must", "throw", "error"}},
		"included words also excluded": {Length: 2, Include: []string{"Go"}, Exclude: []string{"Go"}},
		"invalid included word":        {Length: 7, Include: []string{"ínvalid"}},
	}

	for k, tc := range cases {
		if _, err := tc.Generate(); err == nil {
			t.Errorf("Expected %q error, got nil", k)
		}
	}
}

func TestNewPassphrase(t *testing.T) {
	length := 5
	passphrase, err := NewPassphrase(uint64(length), NoList)
	if err != nil {
		t.Errorf("NewPassphrase() failed: %v", err)
	}

	words := strings.Split(passphrase, " ")
	got := len(words)

	if got != length {
		t.Errorf("Expected %d words, got %d", length, got)
	}
}

func TestInvalidNewPassphrase(t *testing.T) {
	_, err := NewPassphrase(0, WordList)
	if err == nil {
		t.Error("Expected \"invalid length\" error, got nil")
	}
}

func TestExcludeWords(t *testing.T) {
	cases := map[string]*Passphrase{
		"No list": {
			words:     []string{"cow", "horse", "bee"},
			Separator: " ",
			Exclude:   []string{"cow", "horse", "beer"},
			List:      NoList,
		},
		"Word list": {
			words:     []string{"about", "abysmal", "accurate"},
			Separator: " ",
			Exclude:   []string{"about"},
			List:      WordList,
		},
		"Syllable list": {
			words:     []string{"alt", "bet", "bang flux"},
			Separator: " ",
			Exclude:   []string{"alt", "flux"},
			List:      SyllableList,
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			tc.excludeWords()

			for _, exc := range tc.Exclude {
				for _, word := range tc.words {
					if exc == word {
						t.Errorf("Found undesired word %q", exc)
					}
				}
			}
		})
	}
}

func TestPassphraseEntropy(t *testing.T) {
	cases := []struct {
		desc     string
		list     list
		expected float64
	}{
		{
			desc: "No list",
			list: NoList,
		},
		{
			desc:     "Word list",
			list:     WordList,
			expected: 56.64641721601138,
		},
		{
			desc:     "Syllable list",
			list:     SyllableList,
			expected: 53.225386214754,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			p := &Passphrase{
				Length:    4,
				List:      tc.list,
				Separator: "/",
				Include:   []string{"atoll"},
			}

			p.Generate()

			// NoList entropy changes everytime as it generates random words
			if getFuncName(tc.list) == "NoList" {
				secretLength := len(strings.Join(p.words, "")) - (len(p.Separator) * int(p.Length))
				tc.expected = math.Log2(math.Pow(float64(26), float64(secretLength)))
			}

			got := p.Entropy()
			if got != tc.expected {
				t.Errorf("Expected %f, got %f", tc.expected, got)
			}
		})
	}
}

func TestPassphraseEntropyNoSecret(t *testing.T) {
	p := &Passphrase{
		Length:    7,
		List:      NoList,
		Separator: "/",
	}

	var expected float64 = 0
	got := p.Entropy()
	if got != expected {
		t.Errorf("Expected %f, got %f", expected, got)
	}
}
