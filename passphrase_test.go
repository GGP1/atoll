package atoll_test

import (
	"strings"
	"testing"

	"github.com/GGP1/atoll"
)

func TestNewPassphrase(t *testing.T) {
	passphrase, err := atoll.NewPassphrase(5, atoll.NoList)
	if err != nil {
		t.Errorf("Failed generating the passphrase: %v", err)
	}

	t.Log(passphrase)
}

func TestGeneratePassphrase(t *testing.T) {
	t.Run("No list", TestGeneratePassphrase_NoList)
	t.Run("Word list", TestGeneratePassphrase_WordList)
	t.Run("Syllable list", TestGeneratePassphrase_SyllableList)
}

var passphrases = []*atoll.Passphrase{
	{Length: 14, Separator: "/", Include: []string{}, Exclude: []string{}},
	{Length: 4, Separator: "", Include: []string{"apple"}, Exclude: []string{"banana"}},
	{Length: 6, Separator: "==", Include: []string{"test"}, Exclude: []string{}},
	{Length: 10, Separator: " ", Include: []string{"background"}, Exclude: []string{}},
}

func TestGeneratePassphrase_NoList(t *testing.T) {
	for _, p := range passphrases {
		p.List = atoll.NoList
		if err := p.Generate(); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		// min word length: 3 - max word length: 12
		phraseLength := int(p.Length) + len(p.Separator)
		min := 3 * phraseLength
		max := 12 * phraseLength

		if len(p.Secret) < min || len(p.Secret) > max {
			t.Errorf("Wrong passphrase length, expected it between %d and %d, got: %d", min, max, len(p.Secret))
		}

		if !strings.ContainsAny(p.Secret, p.Separator) {
			t.Errorf("Passphrase does not include the separator (%s) as expected", p.Separator)
		}
	}
}

func TestGeneratePassphrase_WordList(t *testing.T) {
	for _, p := range passphrases {
		p.List = atoll.WordList
		if err := p.Generate(); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		if !strings.ContainsAny(p.Secret, p.Separator) {
			t.Errorf("Passphrase does not include the separator (%s) as expected", p.Separator)
		}
	}
}

func TestGeneratePassphrase_SyllableList(t *testing.T) {
	for _, p := range passphrases {
		p.List = atoll.SyllableList
		if err := p.Generate(); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		if !strings.ContainsAny(p.Secret, p.Separator) {
			t.Errorf("Passphrase does not include the separator (%s) as expected", p.Separator)
		}
	}
}

func TestIncludeWords(t *testing.T) {
	for _, p := range passphrases {
		p.List = atoll.WordList
		if err := p.Generate(); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		for _, incl := range p.Include {
			if !strings.Contains(p.Secret, incl) {
				t.Error("Passphrase does not contain an included word")
			}
		}
	}
}

func TestExcludeWords(t *testing.T) {
	for _, p := range passphrases {
		p.List = atoll.WordList
		if err := p.Generate(); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		for _, excl := range p.Exclude {
			if strings.Contains(p.Secret, excl) {
				t.Errorf("atoll: word %s was not removed from the passphrase", excl)
			}
		}
	}
}
