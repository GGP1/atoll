package atoll

import (
	"strings"
	"testing"
)

func TestPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"No list":        {Length: 14, Separator: "/", Include: []string{}, Exclude: []string{}, List: NoList},
		"Word list":      {Length: 4, Separator: "", Include: []string{"apple"}, Exclude: []string{"banána"}, List: WordList},
		"Syllable list":  {Length: 6, Separator: "==", Include: []string{"test"}, Exclude: []string{}, List: SyllableList},
		"Default values": {Length: 10, Include: []string{"background"}, Exclude: []string{"unit"}},
	}

	for k, tc := range cases {
		passphrase, err := NewSecret(tc)
		if err != nil {
			t.Errorf("%s: NewSecret() failed: %v", k, err)
		}

		words := strings.Split(passphrase, tc.Separator)
		if len(words) != int(tc.Length) {
			t.Errorf("%s: Expected %d words, got %d", k, tc.Length, len(words))
		}

		if !strings.Contains(passphrase, tc.Separator) {
			t.Errorf("%s: The separator %q is not used", k, tc.Separator)
		}

		for _, inc := range tc.Include {
			if !strings.Contains(passphrase, inc) {
				t.Errorf("%s: Expected %q to be included", k, inc)
			}
		}

		for _, exc := range tc.Exclude {
			if strings.Contains(passphrase, exc) {
				t.Errorf("%s: Expected %q not to be included", k, exc)
			}
		}
	}
}

func TestInvalidPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"invalid length":               {Length: 0},
		"len(Include) > Length":        {Length: 2, Include: []string{"must", "throw", "error"}},
		"included words also excluded": {Length: 2, Include: []string{"Go"}, Exclude: []string{"Go"}},
	}

	for k, tc := range cases {
		_, err := NewSecret(tc)
		if err == nil {
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
		tc.excludeWords()

		words := strings.Split(tc.secret, tc.Separator)

		for _, exc := range tc.Exclude {
			for _, word := range words {
				if exc == word {
					t.Errorf("%s: found undesired word %q", k, exc)

				}
			}
		}
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
