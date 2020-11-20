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
		if strings.Contains(incl, excl) {
			return "", fmt.Errorf("word %q cannot be included and excluded", excl)
		}
	}

	// Generate the secret with the list specified
	p.List(p)
	// Include and exclude words
	p.includeWords()
	p.excludeWords(p.List)

	return p.secret, nil
}

// Determine include indices and replace the existing word with an included one.
//
// This way we are replacing words instead of reserving indices for them, but
// doing it the other way makes the algorithm much more complicated to follow.
func (p *Passphrase) includeWords() {
	if len(p.Include) == 0 {
		return
	}

	indices := make([]int, len(p.Include))
	pwdIndices := make([]int, int(p.Length))

	for i := 0; i < int(p.Length); i++ {
		pwdIndices[i] = i
	}

	for i := range indices {
		n := randInt(len(pwdIndices))
		index := pwdIndices[n]

		// Remove the selected index from the array to not overwrite them
		pwdIndices = append(pwdIndices[:n], pwdIndices[n+1:]...)

		indices[i] = index
	}

	words := strings.Split(p.secret, p.Separator)

	for i := range words {
		for _, j := range indices {
			if i == j {
				n := randInt(len(p.Include))
				words[i] = p.Include[n]
				// Remove the word used
				p.Include = append(p.Include[:n], p.Include[n+1:]...)
			}
		}
	}

	p.secret = strings.Join(words, p.Separator)
}

// Check if any excluded word is within the secret and (if true)
// replace it with another random word.
func (p *Passphrase) excludeWords(m list) {
	if len(p.Exclude) == 0 {
		return
	}

	words := strings.Split(p.secret, p.Separator)

	for i, word := range words {
		for _, excl := range p.Exclude {
			if word == excl {
				switch getFuncName(m) {
				case "NoList":
					wordLength := randInt(10) + 3
					syllables := make([]string, wordLength)

					for i := 0; i < wordLength; i++ {
						// Take a number from 0 to 10: 0 to 3 add a vowel, 4 to 10 add a constant
						if randInt(11) <= 3 {
							syllables = append(syllables, vowels[randInt(len(vowels))])
						} else {
							syllables = append(syllables, constants[randInt(len(constants))])
						}
					}

					word := strings.Join(syllables, "")
					words[i] = word

				case "WordList":
					words[i] = atollWords[randInt(len(atollWords))]

				case "SyllableList":
					words[i] = atollSyllables[randInt(len(atollSyllables))]
				}
			}
		}
	}

	p.secret = strings.Join(words, p.Separator)
}

// NoList generates a random passphrase without using a list, making the potential attacker work harder.
//
// Words length are randomly selected between 3 and 12 letters.
//
// Selecting a random number between 0 and 10 where 0-3 vowel and 4-10 constant.
func NoList(p *Passphrase) {
	var wg sync.WaitGroup
	passphrase := make([]string, p.Length)

	wg.Add(len(passphrase))
	for i := range passphrase {
		go func(i int, passphrase []string) {
			defer wg.Done()

			wordLength := randInt(10) + 3
			syllables := make([]string, wordLength)

			for j := 0; j < wordLength; j++ {
				if randInt(11) <= 3 {
					syllables = append(syllables, vowels[randInt(len(vowels))])
					continue
				}

				syllables = append(syllables, constants[randInt(len(constants))])
			}

			word := strings.Join(syllables, "")

			passphrase[i] = word
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
