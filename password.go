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

// NewPassword returns a random password.
func NewPassword(length uint64, format []int) (string, error) {
	p := &Password{
		Length: length,
		Format: format,
	}

	if err := p.Generate(); err != nil {
		return "", err
	}

	return p.Secret, nil
}

// Generate generates a random password.
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
	poolLength := len(pool) + len(p.Include)

	if !p.Repeat && int(p.Length) > (poolLength) {
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
		if err := shuffle(len(password), func(i, j int) { password[i], password[j] = password[j], password[i] }); err != nil {
			return "", err
		}
		return p.sanitize(password, pool)
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
	if len(p.Format) == 0 {
		p.Format = []int{1, 2, 3, 4, 5}
	}

	levels := make(map[int]struct{}, len(p.Format))

	for _, v := range p.Format {
		levels[v] = struct{}{}
	}

	chars := make([]string, len(levels))

	for key := range levels {
		if key > 5 {
			return nil, errors.New("atoll: password level must be equal to or lower than 5")
		}

		switch key {
		case 1:
			chars = append(chars, lowerCase)
		case 2:
			chars = append(chars, upperCase)
		case 3:
			chars = append(chars, digit)
		case 4:
			chars = append(chars, space)
		case 5:
			chars = append(chars, special)
		}
	}

	pool := strings.Join(chars, "")

	// Remove excluded characters from the pool
	if p.Exclude != "" {
		split := strings.Split(p.Exclude, "")
		for _, s := range split {
			pool = strings.Replace(pool, s, "", -1)
		}
	}

	return []rune(pool), nil
}

// includeChars returns an array with the positions that include characters will occupy in the password.
//
// This way we are replacing characters instead of reserving indices for them to keep
// the algorithm as simple as possible.
func (p *Password) includeChars(password []rune) []rune {
	chars := []rune(p.Include)
	indices := make([]int, len(p.Include))

	// Create an array with password indices
	pwdIndices := make([]int, p.Length)
	for i := range pwdIndices {
		pwdIndices[i] = i
	}

	// Select an index from the password for each character of "include"
	// pwdIndices[n] -> put an inclChar at this index
	for i := range indices {
		n := randInt(len(pwdIndices))
		idx := pwdIndices[n]

		// Remove the selected index from the array to not overwrite them
		pwdIndices = append(pwdIndices[:n], pwdIndices[n+1:]...)

		indices[i] = idx
	}

	for i := range password {
		// Compare i and random numbers, if they are equal, a random char from "chars"
		// will be appended to the password until "chars" is empty
		for _, index := range indices {
			if i == index {
				n := randInt(len(chars))
				password[i] = chars[n]

				removeElem(&chars, n)
			}
		}
	}

	return password
}
