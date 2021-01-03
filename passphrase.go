package atoll

import (
	"errors"
	"fmt"
	"strings"
)

var (
	vowels    = [5]string{"a", "e", "i", "o", "u"}
	constants = [21]string{"b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n",
		"p", "q", "r", "s", "t", "v", "w", "x", "y", "z"}
)

// Passphrase represents a sequence of words/syllables with a separator between them.
type Passphrase struct {
	secret string

	// Number of words in the passphrase.
	Length uint64

	// Words separator.
	Separator string

	// List used to generate the passphrase.
	List list

	// Words that will be part of the passphrase.
	Include []string

	// Words that won't be part of the passphrase.
	Exclude []string
}

type list func(p *Passphrase)

// NewPassphrase returns a random passphrase.
func NewPassphrase(length uint64, l list) (string, error) {
	p := &Passphrase{
		Length: length,
		List:   l,
	}

	passphrase, err := p.Generate()
	if err != nil {
		return "", err
	}

	return passphrase, nil
}

// Generate generates a random passphrase.
func (p *Passphrase) Generate() (string, error) {
	if p.Length < 1 {
		return "", errors.New("atoll: passphrase length must be equal to or higher than 1")
	}

	if len(p.Include) > int(p.Length) {
		return "", errors.New("atoll: number of words to include exceed the password length")
	}

	for _, incl := range p.Include {
		// Look for words contaning 2/3 bytes characters
		if len(incl) != len([]rune(incl)) {
			return "", fmt.Errorf("atoll: included word %q contains invalid characters", incl)
		}

		// Check for equality between included and excluded words
		for _, excl := range p.Exclude {
			if incl == excl {
				return "", fmt.Errorf("word %q cannot be included and excluded", excl)
			}
		}
	}

	// Defaults
	if p.Separator == "" {
		p.Separator = " "
	}
	if p.List == nil {
		p.List = NoList
	}

	// Generate the passphrase with the list specified
	p.List(p)
	// Include and exclude words
	if len(p.Include) != 0 {
		p.includeWords()
	}
	if len(p.Exclude) != 0 {
		p.excludeWords()
	}

	return p.secret, nil
}

// includeWords randomly inserts included words in the passphrase, replacing already existing words.
func (p *Passphrase) includeWords() {
	words := strings.Split(p.secret, p.Separator)

	for range p.Include {
		words[randInt(len(words))] = p.Include[0]
		p.Include = p.Include[1:]
	}

	p.secret = strings.Join(words, p.Separator)
}

// Check if any excluded word is within the secret and (if true) replace it with another random word.
func (p *Passphrase) excludeWords() {
	words := strings.Split(p.secret, p.Separator)

	for i, word := range words {
		for _, excl := range p.Exclude {
			if word == excl {
				switch getFuncName(p.List) {
				case "NoList":
					words[i] = generateRandomWord()

				case "WordList":
					words[i] = atollWords[randInt(len(atollWords))]

				case "SyllableList":
					words[i] = atollSyllables[randInt(len(atollSyllables))]
				}

				p.secret = strings.Join(words, p.Separator)
				// Use recursion to repeat the process until there is no excluded word
				p.excludeWords()
			}
		}
	}
}

// NoList generates a random passphrase without using a list, making the potential attacker work harder.
func NoList(p *Passphrase) {
	passphrase := make([]string, p.Length)

	for i := range passphrase {
		passphrase[i] = generateRandomWord()
	}

	p.secret = strings.Join(passphrase, p.Separator)
}

// WordList generates a passphrase using a wordlist (18,325 long).
func WordList(p *Passphrase) {
	passphrase := make([]string, p.Length)

	for i := range passphrase {
		passphrase[i] = atollWords[randInt(len(atollWords))]
	}

	p.secret = strings.Join(passphrase, p.Separator)
}

// SyllableList generates a passphrase using a syllable list (10,129 long).
func SyllableList(p *Passphrase) {
	passphrase := make([]string, p.Length)

	for i := range passphrase {
		passphrase[i] = atollSyllables[randInt(len(atollSyllables))]
	}

	p.secret = strings.Join(passphrase, p.Separator)
}

// generateRandomWord returns a random sword without using any list or dictionary.
func generateRandomWord() string {
	// Words length are randomly selected between 3 and 12 letters.
	wordLength := randInt(10) + 3
	syllables := make([]string, wordLength)

	for i := 0; i < wordLength; i++ {
		idx := randInt(len(syllables))
		// Select a number from 0 to 10, 0-3 is a vowel, else a consonant
		if randInt(11) <= 3 {
			syllables[idx] = vowels[randInt(len(vowels))]
			continue
		}

		syllables[idx] = constants[randInt(len(constants))]
	}

	return strings.Join(syllables, "")
}
