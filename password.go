package atoll

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

// Password level.
const (
	Lower = Level("abcdefghijklmnopqrstuvwxyz")
	Upper = Level("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	Digit = Level("0123456789")
	// Space cannot be the only level used, as the sanitizer trims leading and trailing
	// spaces the resulting secret would be degenerate.
	Space   = Level(" ")
	Special = Level("&$%@#|/\\=\"*~^`'.?!,;:-+_(){}[]<>")
)

// maxPatternRetries is the number of times the password is shuffled trying to get
// rid of common patterns before giving up.
const maxPatternRetries = 100

// Level represents a determined group of characters.
type Level string

// Password represents a sequence of characters required for access to a computer system.
type Password struct {
	pool []byte

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
func NewPassword(length uint64, levels []Level) ([]byte, error) {
	p := &Password{
		Length: length,
		Levels: levels,
	}

	return p.Generate()
}

// Generate generates a random password.
func (p *Password) Generate() ([]byte, error) {
	password, err := p.generate()
	if err != nil {
		return nil, fmt.Errorf("atoll: %w", err)
	}

	return password, nil
}

func (p *Password) generate() ([]byte, error) {
	if err := p.validateParams(); err != nil {
		return nil, err
	}

	p.generatePool()

	// A pool made up of spaces only would be entirely removed by the sanitizer
	if bytes.IndexFunc(p.pool, func(r rune) bool { return r != ' ' }) == -1 {
		return nil, errors.New("the pool contains spaces only")
	}

	if !p.Repeat && int(p.Length) > p.capacity() {
		return nil, errors.New("password length is higher than the pool and repetition is turned off")
	}

	password, err := p.buildPassword()
	if err != nil {
		return nil, err
	}

	return p.sanitize(password)
}

// capacity returns the number of characters available to build the password when
// repetition is turned off.
//
// Characters that are included and already in the pool don't add up, they are removed
// from it as soon as they are used.
func (p *Password) capacity() int {
	capacity := len(p.pool)
	for _, c := range p.Include {
		if !bytes.ContainsRune(p.pool, c) {
			capacity++
		}
	}

	return capacity
}

// buildPassword creates the password.
func (p *Password) buildPassword() ([]byte, error) {
	var (
		password = make([]byte, 0, p.Length)
		err      error
	)

	// Add included characters
	for _, c := range p.Include {
		password, err = p.randInsert(password, byte(c))
		if err != nil {
			return nil, err
		}
	}

	// Add one character of each level only if we can guarantee it
	if int(p.Length) > len(p.Levels) {
		for _, lvl := range p.Levels {
			if len(password) >= int(p.Length) {
				break
			}

			// The level may be already represented by an included character
			if bytes.ContainsAny(password, string(lvl)) {
				continue
			}

			// Take the characters of the level that are still in the pool, the others
			// were either excluded or already used
			available := p.levelPool(lvl)
			if len(available) == 0 {
				// The space may be removed by the sanitizer anyway, it's never guaranteed
				if lvl == Space {
					continue
				}

				return nil, fmt.Errorf("the %s level cannot be guaranteed, all its characters were either excluded or used by the characters to include", levelName(lvl))
			}

			idx, err := randInt(len(available))
			if err != nil {
				return nil, err
			}

			password, err = p.randInsert(password, available[idx])
			if err != nil {
				return nil, err
			}
		}
	}

	// Subtract the number of characters already added to the password from the total length
	remaining := int(p.Length) - len(password)
	for i := 0; i < remaining; i++ {
		idx, err := randInt(len(p.pool))
		if err != nil {
			return nil, err
		}

		password, err = p.randInsert(password, p.pool[idx])
		if err != nil {
			return nil, err
		}
	}

	return password, nil
}

// generatePool sets the pool of characters the password will be built from.
func (p *Password) generatePool() {
	p.pool = p.newPool()
}

// newPool returns the set of characters that may be part of the password: the ones of
// every level, without duplicates and without the excluded ones.
func (p *Password) newPool() []byte {
	var excluded, added [256]bool
	for i := 0; i < len(p.Exclude); i++ {
		excluded[p.Exclude[i]] = true
	}

	n := 0
	for _, lvl := range p.Levels {
		n += len(lvl)
	}

	pool := make([]byte, 0, n)
	for _, lvl := range p.Levels {
		for i := 0; i < len(lvl); i++ {
			char := lvl[i]
			// Duplicated characters would be more likely to be chosen than the others
			if added[char] || excluded[char] {
				continue
			}

			added[char] = true
			pool = append(pool, char)
		}
	}

	return pool
}

// levelPool returns the characters of the level that are still in the pool.
func (p *Password) levelPool(lvl Level) []byte {
	chars := make([]byte, 0, len(lvl))
	for i := 0; i < len(lvl); i++ {
		if bytes.IndexByte(p.pool, lvl[i]) != -1 && bytes.IndexByte(chars, lvl[i]) == -1 {
			chars = append(chars, lvl[i])
		}
	}

	return chars
}

// randInsert returns password with char inserted in a random position and removes char from pool in
// case p.Repeat is set to false.
func (p *Password) randInsert(password []byte, char byte) ([]byte, error) {
	i, err := randInt(len(password) + 1)
	if err != nil {
		return nil, err
	}

	if int(i) == len(password) {
		password = append(password, char)
	} else {
		password = append(password[:i+1], password[i:]...)
		password[i] = char
	}

	if !p.Repeat {
		// Remove character used
		if idx := bytes.IndexByte(p.pool, char); idx != -1 {
			p.pool = append(p.pool[:idx], p.pool[idx+1:]...)
		}
	}

	return password, nil
}

// sanitize clears common patterns and removes leading and trailing spaces.
func (p *Password) sanitize(password []byte) ([]byte, error) {
	password = bytes.TrimSpace(password)
	// In case any space was removed, generate new characters and add
	// them to the password to meet the length required
	if len(password) < int(p.Length) {
		offset := int(p.Length) - len(password)
		if !p.Repeat && len(p.pool) < offset {
			return nil, errors.New("not enough characters left to replace the spaces removed from the edges of the password")
		}

		for i := 0; i < offset; i++ {
			idx, err := randInt(len(p.pool))
			if err != nil {
				return nil, err
			}

			// Add remaining characters in random positions
			password, err = p.randInsert(password, p.pool[idx])
			if err != nil {
				return nil, err
			}
		}
	}

	// Shuffle the password in case it has common patterns until it doesn't
	for i := 0; commonPatterns.Match(password); i++ {
		if i == maxPatternRetries {
			return nil, errors.New("failed generating a password without common patterns")
		}

		var err error
		password, err = shuffle(password)
		if err != nil {
			return nil, err
		}
	}

	return password, nil
}

func (p *Password) validateParams() error {
	if p.Length < 1 {
		return errors.New("invalid password length")
	}

	if len(p.Levels) == 0 {
		return errors.New("no levels were specified")
	}

	if bytes.ContainsAny([]byte(p.Include), p.Exclude) {
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

	if !p.Repeat {
		unique := make(map[rune]struct{}, len(p.Include))
		for _, incl := range p.Include {
			if _, ok := unique[incl]; ok {
				return fmt.Errorf("character %q is included twice and repetition is turned off", incl)
			}
			unique[incl] = struct{}{}
		}
	}

	return p.validateLevels()
}

// validateLevels checks if Exclude contains all the characters of a level that is in Levels.
func (p *Password) validateLevels() error {
	var excluded [256]bool
	for i := 0; i < len(p.Exclude); i++ {
		excluded[p.Exclude[i]] = true
	}

	for _, lvl := range p.Levels {
		if len(lvl) < 1 {
			return errors.New("empty levels aren't allowed")
		}

		// Count distinct characters, a character repeated in Exclude must not
		// be counted more than once
		available := 0
		for i := 0; i < len(lvl); i++ {
			if !excluded[lvl[i]] {
				available++
			}
		}

		if available == 0 {
			return fmt.Errorf("%s level is used and all its characters are excluded", levelName(lvl))
		}
	}

	return nil
}

// levelName returns a human readable name for the level given.
func levelName(lvl Level) string {
	switch lvl {
	case Lower:
		return "lowercase"
	case Upper:
		return "uppercase"
	case Digit:
		return "digit"
	case Space:
		return "space"
	case Special:
		return "special"
	default:
		return "custom"
	}
}

// Entropy returns the password entropy in bits.
//
// Characters that are included aren't taken into account: as the attacker is assumed to know
// the method used, they are fixed and known values that reduce the number of characters that
// are randomly chosen.
//
// The value returned is an approximation: the randomness of the positions in which the
// included characters are inserted isn't taken into account (it errs on the low side),
// while guaranteeing one character of each level and re-shuffling the passwords that
// contain common patterns make the distribution slightly non-uniform (on the high side).
func (p *Password) Entropy() float64 {
	pool := p.newPool()
	// Included characters are known, only the rest of them is randomly chosen
	random := int(p.Length) - len(p.Include)
	if random <= 0 || len(pool) == 0 {
		return 0
	}

	if p.Repeat {
		return float64(random) * math.Log2(float64(len(pool)))
	}

	// Characters are sampled without replacement, the pool shrinks by one every time a
	// character is used, included ones as well
	available := len(pool)
	for _, c := range p.Include {
		if bytes.ContainsRune(pool, c) {
			available--
		}
	}

	var entropy float64
	for i := 0; i < random && available-i > 0; i++ {
		entropy += math.Log2(float64(available - i))
	}

	return entropy
}
