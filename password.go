package atoll

import (
	"errors"
	"fmt"
	"math"
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
	pool string

	// Password length.
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
}

// NewPassword returns a random password.
func NewPassword(length uint64, format []int) (string, error) {
	p := &Password{
		Length: length,
		Format: format,
	}

	return p.Generate()
}

// Generate generates a random password.
func (p *Password) Generate() (string, error) {
	password, err := p.generate()
	if err != nil {
		return "", fmt.Errorf("atoll: %v", err)
	}

	return password, nil
}

func (p *Password) generate() (string, error) {
	if p.Length < 1 {
		return "", errors.New("invalid password length")
	}

	if strings.ContainsAny(p.Include, p.Exclude) {
		return "", errors.New("included characters cannot be excluded")
	}

	// Check if include contains 2/3 bytes characters
	for _, incl := range p.Include {
		if len(string(incl)) != 1 {
			return "", fmt.Errorf("include contains invalid characters: %q", string(incl))
		}
	}

	if len(p.Include) > int(p.Length) {
		return "", errors.New("characters to include exceed the password length")
	}

	// Get rid of duplicated levels, or return an error if it is invalid
	levels := make(map[int]struct{})
	for _, l := range p.Format {
		if l < 1 || l > 5 {
			return "", errors.New("format levels must be between 1 and 5")
		}
		levels[l] = struct{}{}
	}

	if err := p.validateLevels(levels); err != nil {
		return "", err
	}

	p.generatePool(levels)

	if !p.Repeat && int(p.Length) > (len(p.pool)+len(p.Include)) {
		return "", errors.New("password length is higher than the pool and repetition is turned off")
	}

	password := p.initPassword(levels)
	// Subtract the number of characters already added to the password from the total length
	remaining := int(p.Length) - len(password)

	for i := 0; i < remaining; i++ {
		c := p.pool[randInt(len(p.pool))]
		password = randInsert(password, c)

		if !p.Repeat {
			// Remove element used
			p.pool = strings.Replace(p.pool, string(c), "", 1)
		}
	}

	password = p.sanitize(password)

	return password, nil
}

// generatePool takes the format specified by the user and creates the pool to generate a random password.
func (p *Password) generatePool(levels map[int]struct{}) {
	if len(p.Format) == 0 {
		// Use all the levels by default
		p.pool = lowerCase + upperCase + digit + space + special
		return
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

	p.pool = strings.Join(chars, "")

	if p.Exclude != "" {
		// Remove excluded characters from the pool
		exclChars := strings.Split(p.Exclude, "")
		for _, c := range exclChars {
			p.pool = strings.Replace(p.pool, c, "", 1)
		}
	}
}

// initPassword creates the password, adds any included word and makes sure that it contains
// at least 1 character of each level (only if p.Length is longer than levels).
func (p *Password) initPassword(levels map[int]struct{}) string {
	var (
		password string
		char     byte
	)

	// Add included characters
	for i := range p.Include {
		c := p.Include[i]
		password = randInsert(password, c)

		if !p.Repeat {
			// Remove character used
			p.pool = strings.Replace(p.pool, string(c), "", 1)
		}
	}

	if int(p.Length) < len(levels) {
		return password
	}

	for level := range levels {
	repeat:
		switch level {
		case 1:
			char = lowerCase[randInt(len(lowerCase))]
		case 2:
			char = upperCase[randInt(len(upperCase))]
		case 3:
			char = digit[randInt(len(digit))]
		case 4:
			char = ' ' // space
		case 5:
			char = special[randInt(len(special))]
		}

		// If the pool does not contain the character selected it's because
		// it was either excluded or already used
		if !strings.Contains(p.pool, string(char)) {
			goto repeat
		}

		password = randInsert(password, char)

		if !p.Repeat {
			// Remove character used
			p.pool = strings.Replace(p.pool, string(char), "", 1)
		}
	}

	return password
}

// sanitize clears common patterns and removes leading and trailing spaces.
func (p *Password) sanitize(password string) string {
	password = strings.TrimSpace(password)
	// In case any space was removed, generate new characters and add
	// them to the password to meet the length required
	if len(password) < int(p.Length) {
		offset := int(p.Length) - len(password)

		for i := 0; i < offset; i++ {
			// Add remaining characters in random positions
			password = randInsert(password, p.pool[randInt(len(p.pool))])
		}
	}

	// Shuffle the password in case it has common patterns until it doesn't
repeat:
	if regexp.MustCompile(commonPatterns).MatchString(password) {
		password = shuffle([]rune(password))
		goto repeat
	}

	return password
}

// validateLevels checks if Exclude contains all the characters of a level that is in Format.
func (p *Password) validateLevels(levels map[int]struct{}) error {
	// If the user excluded the space character and used the space level, return error
	if _, ok := levels[4]; ok && strings.Contains(p.Exclude, " ") {
		return errors.New("space level is used and its character is excluded")
	}

	// The other levels have more than 9 characters
	if len(p.Exclude) < 10 {
		return nil
	}

	var (
		set       string
		levelName string
	)

	for l := range levels {
		fail := true

		switch l {
		case 1:
			set = lowerCase
			levelName = "lowerCase"
		case 2:
			set = upperCase
			levelName = "upperCase"
		case 3:
			set = digit
			levelName = "digit"
		case 4:
			continue // skip as it's already checked above
		case 5:
			set = special
			levelName = "special"
		}

		for _, excl := range p.Exclude {
			if !strings.Contains(set, string(excl)) {
				fail = false
				break
			}
		}

		if fail {
			return fmt.Errorf("%s level is used and all its characters are excluded", levelName)
		}
	}

	return nil
}

// Entropy returns the bits of entropy of the password.
func (p *Password) Entropy() float64 {
	var poolLength int

	levels := make(map[int]struct{})
	for _, l := range p.Format {
		if l > 0 || l < 6 {
			levels[l] = struct{}{}
		}
	}

	for level := range levels {
		switch level {
		case 1:
			poolLength += len(lowerCase)
		case 2:
			poolLength += len(upperCase)
		case 3:
			poolLength += len(digit)
		case 4:
			poolLength += len(space)
		case 5:
			poolLength += len(special)
		}
	}

	// Remove characters from exclude that aren't in the pool
	for _, excl := range p.Exclude {
		if len(string(excl)) != 1 {
			p.Exclude = strings.ReplaceAll(p.Exclude, string(excl), "")
		}
	}

	poolLength -= len(p.Exclude)

	return math.Log2(math.Pow(float64(poolLength), float64(p.Length)))
}
