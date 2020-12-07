package atoll

import (
	"errors"
	"fmt"
	"strings"
	"sync"
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

	if p.Separator == "" {
		p.Separator = " "
	}

	if p.List == nil {
		p.List = NoList
	}

	incl := strings.Join(p.Include, p.Separator)
	for _, excl := range p.Exclude {
		if incl == excl {
			return "", fmt.Errorf("word %q cannot be included and excluded", excl)
		}
	}

	// Generate the secret with the list specified
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

// Determine include indices and replace the existing word with an included one.
func (p *Passphrase) includeWords() {
	indices := make(map[int]struct{}, len(p.Include))

	// Take a unique random index for each word
	for range p.Include {
	repeat:
		n := randInt(int(p.Length))
		if _, ok := indices[n]; !ok {
			indices[n] = struct{}{}
			continue
		}
		goto repeat
	}

	words := strings.Split(p.secret, p.Separator)

	for i := range indices {
		words[i] = p.Include[0]
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
	var wg sync.WaitGroup
	passphrase := make([]string, p.Length)

	wg.Add(len(passphrase))
	for i := range passphrase {
		go func(i int, passphrase []string) {
			defer wg.Done()
			passphrase[i] = generateRandomWord()
		}(i, passphrase)
	}
	wg.Wait()

	p.secret = strings.Join(passphrase, p.Separator)
}

// WordList generates a passphrase using a wordlist (18,325 long).
func WordList(p *Passphrase) {
	words := make([]string, p.Length)

	for i := range words {
		words[i] = atollWords[randInt(len(atollWords))]
	}

	p.secret = strings.Join(words, p.Separator)
}

// SyllableList generates a passphrase using a syllable list (10,129 long).
func SyllableList(p *Passphrase) {
	passphrase := make([]string, p.Length)

	for i := range passphrase {
		passphrase[i] = atollSyllables[randInt(len(atollSyllables))]
	}

	p.secret = strings.Join(passphrase, p.Separator)
}

// generateRandomWord returns a word without using any list or dictionary.
func generateRandomWord() string {
	// Words length are randomly selected between 3 and 12 letters.
	wordLength := randInt(10) + 3
	syllables := make([]string, wordLength)

	for j := 0; j < wordLength; j++ {
		// Select a number from 0 to 10, 0-3 is a vowel, else a consonant
		if randInt(11) <= 3 {
			syllables = append(syllables, vowels[randInt(len(vowels))])
			continue
		}

		syllables = append(syllables, constants[randInt(len(constants))])
	}

	return strings.Join(syllables, "")
}
