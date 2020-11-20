package atoll

import (
	"errors"
	"regexp"
	"strings"
)

const (
	lowerCase    = "abcdefghijklmnopqrstuvwxyz"         // Level 1
	upperCase    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"         // Level 2
	digit        = "0123456789"                         // Level 3
	space        = " "                                  // Level 4
	special      = "&$%@#|/\\=\"*~^`'.?!,;:-+_(){}[]<>" // Level 5
	extendedUTF8 = `¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄ
	ÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷
	øùúûüýþÿ`  // Level 6
)

// Password represents a sequence of characters required for access to a computer system.
type Password struct {
	Length uint64

	// Each format element is a level that determines the
	// set of characters to take into account when creating
	// the password pool.
	//
	// Levels: 1. lowercase, 2. uppercase, 3. digit,
	// 4. space, 5. special.
	Format []uint8

	// Characters that will be part of the password.
	Include string

	// Characters that won't be part of the password.
	Exclude string

	// Character repetition.
	Repeat bool
}

// NewPassword returns a random password.
func NewPassword(length uint64, format []uint8) (string, error) {
	p := &Password{
		Length: length,
		Format: format,
	}

	password, err := p.Generate()
	if err != nil {
		return "", err
	}

	return password, nil
}

// Generate generates a random password.
func (p *Password) Generate() (string, error) {
	if p.Length < 1 {
		return "", errors.New("atoll: invalid password length")
	}

	if strings.ContainsAny(p.Include, p.Exclude) {
		return "", errors.New("atoll: included characters cannot be excluded")
	}

	if len([]rune(p.Include)) > int(p.Length) {
		return "", errors.New("atoll: characters to include exceed the password length")
	}

	pool, err := p.generatePool()
	if err != nil {
		return "", err
	}

	if !p.Repeat && int(p.Length) > len(pool)+len([]rune(p.Include)) {
		return "", errors.New("atoll: password length is higher than the pool and repetition is turned off")
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
	verified := p.verify(password, pool)

	return verified, nil
}

// generatePool takes the format specified by the user and creates the pool to generate a random password.
func (p *Password) generatePool() ([]rune, error) {
	if len(p.Format) == 0 {
		p.Format = []uint8{1, 2, 3, 4, 5}
	}

	levels := make(map[uint8]struct{}, len(p.Format))

	for _, v := range p.Format {
		levels[v] = struct{}{}
	}

	chars := make([]string, len(levels))

	for key := range levels {
		if key < 1 || key > 6 {
			return nil, errors.New("atoll: format level must be between 1 and 5")
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
		case 6:
			chars = append(chars, extendedUTF8)
		}
	}

	pool := strings.Join(chars, "")

	// Remove excluded characters from the pool
	if p.Exclude != "" {
		exclChars := strings.Split(p.Exclude, "")
		for _, c := range exclChars {
			pool = strings.Replace(pool, c, "", -1)
		}
	}

	return []rune(pool), nil
}

// includeChars choses randomly len(Include) indices and replaces the password
// characters in the matching indices with characters inside Include.
//
// This way we are replacing characters instead of reserving indices for them to keep
// the algorithm as simple as possible.
func (p *Password) includeChars(password []rune) []rune {
	chars := []rune(p.Include)
	indices := make([]int, len(chars))

	// Create an array with password indices
	pwdIndices := make([]int, p.Length)
	for i := range pwdIndices {
		pwdIndices[i] = i
	}

	// Select an index from the password for each character of "include"
	for i := range indices {
		n := randInt(len(pwdIndices))
		idx := pwdIndices[n]

		// Remove the selected index from the array to not overwrite them
		pwdIndices = append(pwdIndices[:n], pwdIndices[n+1:]...)

		indices[i] = idx
	}

	for i := range password {
		// Compare i and random numbers, if they are equal, a random char from "chars"
		// will be appended to the password until it's empty
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

// verify clears common patterns and removes leading and trailing spaces.
func (p *Password) verify(password, pool []rune) string {
	// If found common patterns, shuffle password. Repeat until it's strong enough
	weak := regexp.MustCompile(commonPatterns).MatchString(string(password))
	if weak {
		shuffle(password)
		return p.verify(password, pool)
	}

	pwd := strings.TrimSpace(string(password))
	// If it spaces were removed generate new characters and add
	// them to the pwd to meet the length required
	if len([]rune(pwd)) < int(p.Length) {
		diff := int(p.Length) - len(pwd)
		for i := 0; i < diff; i++ {
			pwd += string(pool[randInt(len(pool))])
		}
	}

	return pwd
}
