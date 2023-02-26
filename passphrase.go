package atoll

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

var (
	vowels     = [5]string{"a", "e", "i", "o", "u"}
	consonants = [21]string{
		"b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n",
		"p", "q", "r", "s", "t", "v", "w", "x", "y", "z",
	}
)

const (
	noListType       = "NoList"
	wordListType     = "WordList"
	syllableListType = "SyllableList"
)

// Passphrase represents a sequence of words/syllables with a separator between them.
type Passphrase struct {
	// List used to generate the passphrase.
	List list
	// Words separator.
	Separator string
	words     [][]byte
	// Words that will be part of the passphrase.
	Include []string
	// Words that won't be part of the passphrase.
	Exclude []string
	// Number of words in the passphrase.
	Length uint64
}

type list func(p *Passphrase, length int)

// NewPassphrase returns a random passphrase.
func NewPassphrase(length uint64, l list) ([]byte, error) {
	p := &Passphrase{
		Length: length,
		List:   l,
	}

	return p.Generate()
}

// Generate generates a random passphrase.
func (p *Passphrase) Generate() ([]byte, error) {
	passphrase, err := p.generate()
	if err != nil {
		return nil, fmt.Errorf("atoll: %v", err)
	}

	return passphrase, nil
}

func (p *Passphrase) generate() ([]byte, error) {
	if err := p.validateParams(); err != nil {
		return nil, err
	}

	// Defaults
	if p.Separator == "" {
		p.Separator = " "
	}
	if p.List == nil {
		p.List = NoList
	}

	// Initialize secret slice
	p.words = make([][]byte, p.Length)
	length := int(p.Length) - len(p.Include)

	// Generate the passphrase with the list specified
	p.List(p, length)

	// Include and exclude words
	if len(p.Include) != 0 {
		p.includeWords()
	}
	if len(p.Exclude) != 0 {
		p.excludeWords()
	}

	return bytes.Join(p.words, []byte(p.Separator)), nil
}

func (p *Passphrase) validateParams() error {
	if p.Length < 1 {
		return errors.New("passphrase length must be equal to or higher than 1")
	}

	if len(p.Include) > int(p.Length) {
		return errors.New("number of words to include exceed the password length")
	}

	// Look for 2/3 bytes characters
	if len(p.Separator) != utf8.RuneCountInString(p.Separator) {
		return fmt.Errorf("separator %q contains invalid characters", p.Separator)
	}

	for _, incl := range p.Include {
		// Look for words contaning 2/3 bytes characters
		if len(incl) != utf8.RuneCountInString(incl) {
			return fmt.Errorf("included word %q contains invalid characters", incl)
		}

		// Check for equality between included and excluded words
		for _, excl := range p.Exclude {
			if incl == excl {
				return fmt.Errorf("word %q cannot be included and excluded", excl)
			}
		}
	}

	return nil
}

// includeWords randomly inserts included words in the passphrase.
func (p *Passphrase) includeWords() {
	// Add included words at the end of the secret
	for i, word := range p.Include {
		p.words[int(p.Length)-i-1] = []byte(word)
	}

	// Shuffle the secret so included words aren't always at the end
	for i := range p.words {
		j := randInt(i + 1)
		p.words[i], p.words[j] = p.words[j], p.words[i]
	}
}

// excludeWords checks if any excluded word is within the secret and (if true) replace it with another random word.
func (p *Passphrase) excludeWords() {
	for i, word := range p.words {
		for _, excl := range p.Exclude {
			if bytes.Compare(word, []byte(excl)) == 0 {
				switch getFuncName(p.List) {
				case noListType:
					p.words[i] = genRandWord()

				case wordListType:
					p.words[i] = wordList[randInt(len(wordList))]

				case syllableListType:
					p.words[i] = syllableList[randInt(len(syllableList))]
				}

				// Use recursion to repeat the process until there is no excluded word
				p.excludeWords()
			}
		}
	}
}

// Entropy returns the passphrase entropy in bits.
//
// If the list used is "NoList" the secret must be already generated.
func (p *Passphrase) Entropy() float64 {
	var poolLength int

	switch getFuncName(p.List) {
	case noListType:
		if len(p.words) == 0 {
			return 0
		}

		words := bytes.Join(p.words, []byte(""))
		// Take out the separators from the secret length
		secretLength := len(words) - (len(p.Separator) * int(p.Length))
		return math.Log2(math.Pow(float64(len(vowels)+len(consonants)), float64(secretLength)))
	case wordListType:
		poolLength = len(wordList)
	case syllableListType:
		poolLength = len(syllableList)
	}

	poolLength += len(p.Include) - len(p.Exclude)

	// Separators aren't included in the secret length
	return math.Log2(math.Pow(float64(poolLength), float64(p.Length)))
}

// NoList generates a random passphrase without using a list, making the potential attacker work harder.
func NoList(p *Passphrase, length int) {
	for i := 0; i < length; i++ {
		p.words[i] = genRandWord()
	}
}

// WordList generates a passphrase using a wordlist (18,325 long).
func WordList(p *Passphrase, length int) {
	for i := 0; i < length; i++ {
		p.words[i] = wordList[randInt(len(wordList))]
	}
}

// SyllableList generates a passphrase using a syllable list (10,129 long).
func SyllableList(p *Passphrase, length int) {
	for i := 0; i < length; i++ {
		p.words[i] = syllableList[randInt(len(syllableList))]
	}
}

// genRandWord returns a random word without using any list or dictionary.
func genRandWord() []byte {
	var buf bytes.Buffer
	// Words length are randomly selected between 3 and 12 letters.
	wordLength := int(randInt(10)) + 3
	buf.Grow(wordLength)

	for i := 0; i < wordLength; i++ {
		// Select a number from 0 to 10, 0-3 is a vowel, else a consonant
		if randInt(11) <= 3 {
			buf.WriteString(vowels[randInt(len(vowels))])
		} else {
			buf.WriteString(consonants[randInt(len(consonants))])
		}
	}

	return buf.Bytes()
}
