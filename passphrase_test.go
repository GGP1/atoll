package atoll

import (
	"strings"
	"testing"
)

func TestNewPassphrase(t *testing.T) {
	password, err := NewPassphrase(4, " ", []string{"1234"}, []string{}, NoList)
	if err != nil {
		t.Errorf("Failed generating the passphrase: %v", err)
	}

	t.Log(password)
}

func TestGeneratePassphrase(t *testing.T) {
	t.Run("No list", TestGeneratePassphrase_NoList)
	t.Run("Word list", TestGeneratePassphrase_WordList)
	t.Run("Syllable list", TestGeneratePassphrase_SyllableList)
}

var passphrases = []*Passphrase{
	{Length: 14, Separator: "/", Include: []string{}, Exclude: []string{}},
	{Length: 4, Separator: "", Include: []string{"apple"}, Exclude: []string{"banana"}},
	{Length: 6, Separator: "==", Include: []string{"test"}, Exclude: []string{}},
	{Length: 10, Separator: " ", Include: []string{"background"}, Exclude: []string{}},
}

func TestGeneratePassphrase_NoList(t *testing.T) {
	t.Parallel()

	for _, p := range passphrases {
		if err := p.Generate(NoList); err != nil {
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
	t.Parallel()

	for _, p := range passphrases {
		if err := p.Generate(WordList); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		if !strings.ContainsAny(p.Secret, p.Separator) {
			t.Errorf("Passphrase does not include the separator (%s) as expected", p.Separator)
		}
	}
}

func TestGeneratePassphrase_SyllableList(t *testing.T) {
	t.Parallel()

	for _, p := range passphrases {
		if err := p.Generate(SyllableList); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		if !strings.ContainsAny(p.Secret, p.Separator) {
			t.Errorf("Passphrase does not include the separator (%s) as expected", p.Separator)
		}
	}
}

func TestIncludeWords(t *testing.T) {
	for _, p := range passphrases {
		if err := p.Generate(WordList); err != nil {
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
		if err := p.Generate(WordList); err != nil {
			t.Errorf("Failed generating the passphrase: %v", err)
		}

		for _, excl := range p.Exclude {
			if strings.Contains(p.Secret, excl) {
				t.Errorf("atoll: word %s was not removed from the passphrase", excl)
			}
		}
	}
}
