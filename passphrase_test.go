package atoll

import (
	"strings"
	"testing"
)

func TestPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"No list":        {Length: 14, Separator: "/", Include: []string{}, Exclude: []string{}, List: NoList},
		"Word list":      {Length: 4, Separator: "", Include: []string{"apple", "orange", "watermelon"}, Exclude: []string{}, List: WordList},
		"Syllable list":  {Length: 6, Separator: "==", Include: []string{"test"}, Exclude: []string{}, List: SyllableList},
		"Default values": {Length: 10, Include: []string{"background"}, Exclude: []string{"unit"}},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			passphrase, err := NewSecret(tc)
			if err != nil {
				t.Fatalf("NewSecret() failed: %v", err)
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
		"len(Include) > Length":        {Length: 2, Include: []string{"must", "throw", "error"}},
		"included words also excluded": {Length: 2, Include: []string{"Go"}, Exclude: []string{"Go"}},
		"invalid included word":        {Length: 7, Include: []string{"ínvalid"}},
	}

	for k, tc := range cases {
		if _, err := NewSecret(tc); err == nil {
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
		"No list":       {secret: "cow horse bee", Separator: " ", Exclude: []string{"cow", "horse", "beer"}, List: NoList},
		"Word list":     {secret: "about abysmal accurate", Separator: " ", Exclude: []string{"about"}, List: WordList},
		"Syllable list": {secret: "alt bet bang flux", Separator: " ", Exclude: []string{"alt", "flux"}, List: SyllableList},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			tc.excludeWords()

			words := strings.Split(tc.secret, tc.Separator)

			for _, exc := range tc.Exclude {
				for _, word := range words {
					if exc == word {
						t.Errorf("Found undesired word %q", exc)
					}
				}
			}
		})
	}
}

func TestGetFuncName(t *testing.T) {
	cases := []struct {
		List     func(*Passphrase)
		Expected string
	}{
		{List: NoList, Expected: "NoList"},
		{List: WordList, Expected: "WordList"},
		{List: SyllableList, Expected: "SyllableList"},
	}

	for _, tc := range cases {
		got := getFuncName(tc.List)

		if got != tc.Expected {
			t.Errorf("Expected %q, got %q", tc.Expected, got)
		}
	}
}
