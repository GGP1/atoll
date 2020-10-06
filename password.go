package atoll

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	lowerCase = "abcdefghijklmnopqrstuvwxyz"         // Level 1
	upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"         // Level 2
	digit     = "0123456789"                         // Level 3
	space     = " "                                  // Level 4
	special   = "&$%@#|/\\=\"*~^`'.?!,;:-+_(){}[]<>" // Level 5
)

// Password represents a sequence of characters required for access to a computer system.
type Password struct {
	Secret string
	Length uint64

	// Each format element is a level that determines the
	// set of characters to take into account when creating
	// the password pool.
	//
	// Levels: 1. lowercase, 2. uppercase, 3. digit,
	// 4. space, 5. special.
	Format []int

	// Characters that will be part of the password.
	Include string

	// Characters that won't be part of the password.
	Exclude string

	// Character repetition.
	Repeat bool

	// Entropy tells how hard it will be to guess the passphrase itself even
	// if an attacker knows the method you used to select your passphrase.
	//
	// It's measured in bits: log2(poolLength^secretLength).
	Entropy float64
}

// NewPassword creates a password and returns only the secret.
func NewPassword(length uint64, format []int, include, exclude string, repeat bool) (string, error) {
	p := &Password{
		Length:  length,
		Format:  format,
		Include: include,
		Exclude: exclude,
		Repeat:  repeat,
	}

	if err := p.Generate(); err != nil {
		return "", err
	}

	return p.Secret, nil
}

// Generate generates a random password with the length and format given.
func (p *Password) Generate() error {
	if p.Length < 1 {
		return errors.New("atoll: invalid password length")
	}

	if strings.ContainsAny(p.Include, p.Exclude) {
		return errors.New("atoll: included characters cannot be excluded")
	}

	// Normalize user input
	p.Include = normalize(p.Include)
	invalid, _ := regexp.MatchString(`[[:^graph:]]`, p.Include)
	if invalid {
		return errors.New("atoll: include contains invalid characters")
	}

	if len(p.Include) > int(p.Length) {
		return errors.New("atoll: characters to include exceed the password length")
	}

	pool, err := p.generatePool()
	if err != nil {
		return err
	}
	poolLength := len(pool) + len(p.Include) - len(p.Exclude)

	if !p.Repeat && int(p.Length) > (len(pool)+len(p.Include)) {
		return errors.New("atoll: password length is higher than the pool and repetition is turned off")
	}

	password := make([]rune, p.Length)

	for i := range password {
		char := randInt(len(pool))
		password[i] = pool[char]

		if !p.Repeat {
			removeElem(&pool, char)
		}
	}

	password = p.includeChars(password)
	sanitized, err := p.sanitize(password, pool)
	if err != nil {
		return fmt.Errorf("atoll: %v", err)
	}

	p.Secret = sanitized
	p.Entropy = calculateEntropy(poolLength, len(p.Secret))

	return nil
}

// sanitize clears common patternsand removes leading and trailing spaces.
func (p *Password) sanitize(password, pool []rune) (string, error) {
	// If found common patterns, shuffle password
	weak := regexp.MustCompile(commonPatterns).MatchString(string(password))
	if weak {
		err := shuffle(len(password), func(i, j int) { password[i], password[j] = password[j], password[i] })
		if err != nil {
			return "", err
		}
	}

	pwd := strings.TrimSpace(string(password))
	// If it spaces were removed generate new characters and add
	// them to the pwd to meet the length required
	if len(pwd) < int(p.Length) {
		diff := int(p.Length) - len(pwd)
		for i := 0; i < diff; i++ {
			pwd += string(pool[randInt(len(pool))])
		}
	}

	return pwd, nil
}

// generatePool takes the format specified by the user and creates the pool to generate a random password.
func (p *Password) generatePool() ([]rune, error) {
	// If the format is not specified, set default value
	if p.Format == nil || p.Format[0] == 0 {
		p.Format = []int{1, 2, 3, 4, 5}
	}

	levels := make(map[int]struct{}, len(p.Format))

	for _, v := range p.Format {
		levels[v] = struct{}{}
	}

	characters := make([]string, len(levels))

	for key := range levels {
		if key > 5 {
			return nil, errors.New("atoll: password level must be equal to or lower than 5")
		}

		switch key {
		case 1:
			characters = append(characters, lowerCase)
		case 2:
			characters = append(characters, upperCase)
		case 3:
			characters = append(characters, digit)
		case 4:
			characters = append(characters, space)
		case 5:
			characters = append(characters, special)
		}
	}

	pool := strings.Join(characters, "")

	// Remove excluded characters from the pool
	if p.Exclude != "" {
		split := strings.Split(p.Exclude, "")
		for _, s := range split {
			pool = strings.Replace(pool, s, "", -1)
		}
	}

	return []rune(pool), nil
}

// includeChars returns an array with the positions that include characters will occupy
// in the password.
//
// This way we are replacing characters instead of reserving indices for them to keep
// the algorithm as simple as possible.
func (p *Password) includeChars(password []rune) []rune {
	inclChars := []rune(p.Include)
	inclIndices := make([]int, len(p.Include))

	// Create an array with password indices
	pwdIndices := make([]int, p.Length)
	for i := range pwdIndices {
		pwdIndices[i] = i
	}

	// Select an index from the password for each character of "include"
	// pwdIndices[n] -> put an inclChar at this index
	for j := range inclIndices {
		n := randInt(len(pwdIndices))
		index := pwdIndices[n]

		// Remove the selected index from the array to not overwrite them
		pwdIndices = append(pwdIndices[:n], pwdIndices[n+1:]...)

		inclIndices[j] = index
	}

	for i := range password {
		// Compare i and random numbers, if they are equal, a random char from "inclChars"
		// will be appended to the password until "inclChars" is empty
		for _, index := range inclIndices {
			if i == index {
				inclChar := randInt(len(inclChars))
				password[i] = inclChars[inclChar]

				removeElem(&inclChars, inclChar)
			}
		}
	}

	return password
}
