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
	Length uint64

	// Each format element is a level that determines the
	// set of characters to take into account when creating
	// the password pool.
	//
	// Levels: 1. lowercase, 2. uppercase, 3. digit,
	// 4. space, 5. special, 6. extended UTF8.
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

	// Check if include contains 2/3 bytes characters
	for _, incl := range p.Include {
		if len(string(incl)) != 1 {
			return "", fmt.Errorf("atoll: include contains invalid characters (%v)", incl)
		}
	}

	if strings.ContainsAny(p.Include, p.Exclude) {
		return "", errors.New("atoll: included characters cannot be excluded")
	}

	if len(p.Include) > int(p.Length) {
		return "", errors.New("atoll: characters to include exceed the password length")
	}

	pool, err := p.generatePool()
	if err != nil {
		return "", err
	}

	if !p.Repeat && int(p.Length) > len(pool)+len(p.Include) {
		return "", errors.New("atoll: password length is higher than the pool and repetition is turned off")
	}

	var password string
	passwordLen := int(p.Length) - len(p.Include)

	for i := 0; i < passwordLen; i++ {
		char := string(pool[randInt(len(pool))])
		password = randInsert(password, char)

		if !p.Repeat {
			// Remove element used
			pool = strings.Replace(pool, char, "", 1)
		}
	}

	// Add included characters in random positions
	inclRunes := []rune(p.Include)
	for range inclRunes {
		password = randInsert(password, string(inclRunes[0]))
		inclRunes = inclRunes[1:]
	}

	password = p.verify(password, pool)

	return password, nil
}

// generatePool takes the format specified by the user and creates the pool to generate a random password.
func (p *Password) generatePool() (string, error) {
	if len(p.Format) == 0 {
		p.Format = []uint8{1, 2, 3, 4, 5}
	}

	levels := make(map[uint8]struct{})
	for _, l := range p.Format {
		if l < 1 || l > 5 {
			return "", errors.New("atoll: format level must be between 1 and 5")
		}
		levels[l] = struct{}{}
	}

	var i uint8
	chars := make([]string, len(levels))

	for level := range levels {
		switch level {
		case 1:
			chars[i] = lowerCase
		case 2:
			chars[i] = upperCase
		case 3:
			chars[i] = digit
		case 4:
			chars[i] = space
		case 5:
			chars[i] = special
		}

		i++
	}

	pool := strings.Join(chars, "")

	// Remove excluded characters from the pool
	if p.Exclude != "" {
		exclChars := strings.Split(p.Exclude, "")
		for _, c := range exclChars {
			pool = strings.ReplaceAll(pool, c, "")
		}
	}

	return pool, nil
}

// verify clears common patterns and removes leading and trailing spaces.
func (p *Password) verify(password, pool string) string {
	password = strings.TrimSpace(password)
	// If there were spaces removed, generate new characters and add
	// them to the password to meet the length required
	if len([]rune(password)) < int(p.Length) {
		diff := int(p.Length) - len([]rune(password))

		for i := 0; i < diff; i++ {
			// Add remaining characters in random positions
			password = randInsert(password, string(pool[randInt(len(pool))]))
		}
	}

	// If found common patterns, shuffle password. Repeat until it's strong enough
repeat:
	if regexp.MustCompile(commonPatterns).MatchString(password) {
		password = shuffle([]rune(password))
		goto repeat
	}

	return password
}
