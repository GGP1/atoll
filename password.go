package atoll

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// Password level.
const (
	Lower   = Level("abcdefghijklmnopqrstuvwxyz")
	Upper   = Level("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	Digit   = Level("0123456789")
	Space   = Level(" ")
	Special = Level("&$%@#|/\\=\"*~^`'.?!,;:-+_(){}[]<>")
)

// Level represents a determined group of characters.
type Level string

// Password represents a sequence of characters required for access to a computer system.
type Password struct {
	pool string

	// Characters that will be part of the password.
	Include string
	// Characters that won't be part of the password.
	Exclude string
	// Group of characters used to generate the pool.
	Levels []Level
	// Password length.
	Length uint64
	// Character repetition.
	Repeat bool
}

// NewPassword returns a random password.
func NewPassword(length uint64, levels []Level) (string, error) {
	p := &Password{
		Length: length,
		Levels: levels,
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
	if err := p.validateParams(); err != nil {
		return "", err
	}

	p.generatePool()

	if !p.Repeat && int(p.Length) > (len(p.pool)+len(p.Include)) {
		return "", errors.New("password length is higher than the pool and repetition is turned off")
	}

	password := p.buildPassword()
	password = p.sanitize(password)

	return password, nil
}

// buildPassword creates the password.
func (p *Password) buildPassword() string {
	var password string
	// Add included characters
	for _, c := range p.Include {
		password = p.randInsert(password, byte(c))
	}

	// Add one character of each level only if we can guarantee it
	if int(p.Length) > len(p.Levels) {
		for _, lvl := range p.Levels {
		repeat:
			char := lvl[randInt(len(lvl))]

			// If the pool does not contain the character selected it's because
			// it was either excluded or already used
			if !strings.ContainsRune(p.pool, rune(char)) {
				if lvl == Space {
					continue
				}
				goto repeat
			}

			password = p.randInsert(password, char)
		}
	}

	// Subtract the number of characters already added to the password from the total length
	remaining := int(p.Length) - len(password)
	for i := 0; i < remaining; i++ {
		password = p.randInsert(password, p.pool[randInt(len(p.pool))])
	}

	return password
}

func (p *Password) generatePool() {
	buf := getBuf()
	unique := make(map[Level]struct{})

	for _, lvl := range p.Levels {
		// Ensure that duplicated levels aren't added twice
		if _, ok := unique[lvl]; !ok {
			unique[lvl] = struct{}{}
			buf.Grow(len(lvl))
			buf.WriteString(string(lvl))
		}
	}

	p.pool = buf.String()
	putBuf(buf)

	// Remove excluded characters from the pool
	for _, c := range p.Exclude {
		if idx := strings.IndexRune(p.pool, c); idx != -1 {
			p.pool = p.pool[:idx] + p.pool[idx+1:]
		}
	}
}

// randInsert returns password with char inserted in a random position and removes char from pool in
// case p.Repeat is set to false.
func (p *Password) randInsert(password string, char byte) string {
	i := randInt(len(password) + 1)
	charStr := string(char)
	password = password[:i] + charStr + password[i:]

	if !p.Repeat {
		// Remove character used
		if idx := strings.Index(p.pool, charStr); idx != -1 {
			p.pool = p.pool[:idx] + p.pool[idx+1:]
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
			password = p.randInsert(password, p.pool[randInt(len(p.pool))])
		}
	}

	// Shuffle the password in case it has common patterns until it doesn't
repeat:
	if commonPatterns.MatchString(password) {
		password = shuffle([]rune(password))
		goto repeat
	}

	return password
}

func (p *Password) validateParams() error {
	if p.Length < 1 {
		return errors.New("invalid password length")
	}

	if len(p.Levels) == 0 {
		return errors.New("no levels were specified")
	}

	if strings.ContainsAny(p.Include, p.Exclude) {
		return errors.New("included characters cannot be excluded")
	}

	// Check if include contains 2/3 bytes characters
	for _, incl := range p.Include {
		if incl > 127 {
			return fmt.Errorf("include contains invalid characters: %q", incl)
		}
	}

	if len(p.Include) > int(p.Length) {
		return errors.New("characters to include exceed the password length")
	}

	return p.validateLevels()
}

// validateLevels checks if Exclude contains all the characters of a level that is in Levels.
func (p *Password) validateLevels() error {
	for _, lvl := range p.Levels {
		if len(lvl) > len(p.Exclude) {
			continue
		}
		if len(lvl) < 1 {
			return errors.New("empty levels aren't allowed")
		}

		counter := 0
		for _, excl := range p.Exclude {
			if strings.ContainsRune(string(lvl), excl) {
				counter++
				// Stop counting if the character is a space (as it's only one)
				if lvl == Space {
					break
				}
			}
		}

		if counter == len(lvl) {
			var lvlName string

			switch lvl {
			case Lower:
				lvlName = "lowercase"
			case Upper:
				lvlName = "uppercase"
			case Digit:
				lvlName = "digit"
			case Space:
				lvlName = "space"
			case Special:
				lvlName = "special"
			default:
				lvlName = "custom"
			}

			return fmt.Errorf("%s level is used and all its characters are excluded", lvlName)
		}
	}

	return nil
}

// Entropy returns the password entropy in bits.
func (p *Password) Entropy() float64 {
	var poolLength int
	unique := make(map[Level]struct{})

	for _, lvl := range p.Levels {
		if _, ok := unique[lvl]; !ok {
			unique[lvl] = struct{}{}
			poolLength += len(lvl)
		}
	}
	if p.Exclude != "" {
		for k := range unique {
			for _, c := range p.Exclude {
				if strings.ContainsRune(string(k), c) {
					poolLength--
				}
			}
		}
	}
	poolLength += len(p.Include)
	return math.Log2(math.Pow(float64(poolLength), float64(p.Length)))
}
