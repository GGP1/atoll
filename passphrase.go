package atoll

import (
	"errors"
	"fmt"
	"math"
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
	words []string

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

	return p.Generate()
}

// Generate generates a random passphrase.
func (p *Passphrase) Generate() (string, error) {
	passphrase, err := p.generate()
	if err != nil {
		return "", fmt.Errorf("atoll: %v", err)
	}

	return passphrase, nil
}

func (p *Passphrase) generate() (string, error) {
	if p.Length < 1 {
		return "", errors.New("passphrase length must be equal to or higher than 1")
	}

	if len(p.Include) > int(p.Length) {
		return "", errors.New("number of words to include exceed the password length")
	}

	// Look 2/3 bytes characters
	if len(p.Separator) != len([]rune(p.Separator)) {
		return "", fmt.Errorf("separator %q contains invalid characters", p.Separator)
	}

	for _, incl := range p.Include {
		// Look for words contaning 2/3 bytes characters
		if len(incl) != len([]rune(incl)) {
			return "", fmt.Errorf("included word %q contains invalid characters", incl)
		}

		// Check for equality between included and excluded words
		for _, excl := range p.Exclude {
			if incl == excl {
				return "", fmt.Errorf("word %q cannot be included and excluded", excl)
			}
		}
	}

	// Initialize secret slice (included words will be appended)
	p.words = make([]string, int(p.Length)-len(p.Include))
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

	return strings.Join(p.words, p.Separator), nil
}

// includeWords randomly inserts included words in the passphrase, replacing already existing words.
func (p *Passphrase) includeWords() {
	for _, word := range p.Include {
		p.words = append(p.words, word)
	}

	// Shuffle the secret to avoid having included words always at the end
	for i := range p.words {
		j := randInt(i + 1)
		p.words[i], p.words[j] = p.words[j], p.words[i]
	}
}

// Check if any excluded word is within the secret and (if true) replace it with another random word.
func (p *Passphrase) excludeWords() {
	for i, word := range p.words {
		for _, excl := range p.Exclude {
			if word == excl {
				switch getFuncName(p.List) {
				case "NoList":
					p.words[i] = generateRandomWord()

				case "WordList":
					p.words[i] = atollWords[randInt(len(atollWords))]

				case "SyllableList":
					p.words[i] = atollSyllables[randInt(len(atollSyllables))]
				}

				// Use recursion to repeat the process until there is no excluded word
				p.excludeWords()
			}
		}
	}
}

// NoList generates a random passphrase without using a list, making the potential attacker work harder.
func NoList(p *Passphrase) {
	var wg sync.WaitGroup
	length := int(p.Length) - len(p.Include)

	wg.Add(int(length))
	for i := 0; i < length; i++ {
		go func(i int) {
			p.words[i] = generateRandomWord()
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// WordList generates a passphrase using a wordlist (18,325 long).
func WordList(p *Passphrase) {
	length := int(p.Length) - len(p.Include)

	for i := 0; i < length; i++ {
		p.words[i] = atollWords[randInt(len(atollWords))]
	}
}

// SyllableList generates a passphrase using a syllable list (10,129 long).
func SyllableList(p *Passphrase) {
	length := int(p.Length) - len(p.Include)

	for i := 0; i < length; i++ {
		p.words[i] = atollSyllables[randInt(len(atollSyllables))]
	}
}

// Entropy returns the bits of entropy of the passphrase.
//
// If the list used is "NoList" the secret must be already generated.
func (p *Passphrase) Entropy() float64 {
	var poolLength int

	switch getFuncName(p.List) {
	case "NoList":
		if len(p.words) == 0 {
			return 0
		}
		// Take out the separators from the secret length
		// Included and excluded words aren't taken into account
		secretLength := len(p.words) - (len(p.Separator) * int(p.Length))
		// -26- represents the dictionary length
		return math.Log2(math.Pow(float64(26), float64(secretLength)))
	case "WordList":
		poolLength = 18325
	case "SyllableList":
		poolLength = 10129
	}

	poolLength += len(p.Include) - len(p.Exclude)

	// Separators aren't included in the secret length
	return math.Log2(math.Pow(float64(poolLength), float64(p.Length)))
}

// generateRandomWord returns a random sword without using any list or dictionary.
func generateRandomWord() string {
	// Words length are randomly selected between 3 and 12 letters.
	wordLength := randInt(10) + 3
	syllables := make([]string, wordLength)

	for i := 0; i < wordLength; i++ {
		// Select a number from 0 to 10, 0-3 is a vowel, else a consonant
		if randInt(11) <= 3 {
			syllables[i] = vowels[randInt(len(vowels))]
		} else {
			syllables[i] = constants[randInt(len(constants))]
		}
	}

	return strings.Join(syllables, "")
}
