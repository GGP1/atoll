package atoll

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	cases := []struct {
		desc string
		p    *Password
	}{
		{
			desc: "Test all",
			p: &Password{
				Length:  14,
				Format:  []int{1, 2, 3, 4, 5},
				Include: "kure",
				Exclude: "ad",
				Repeat:  false,
			},
		},
		{
			desc: "Repeat",
			p: &Password{
				Length:  8,
				Format:  []int{1, 4},
				Include: "bee",
				Repeat:  true,
			},
		},
		{
			desc: "Length < levels",
			p: &Password{
				Length:  2,
				Format:  []int{1, 3, 4, 5},
				Include: "!",
			},
		},
		{
			desc: "Default values",
			p: &Password{
				Length: 20,
			},
		},
		{
			desc: "Verify levels",
			p: &Password{
				Length:  35,
				Format:  []int{1, 2, 3, 4, 5},
				Exclude: "0aT&7896a!45awq-=",
				Repeat:  true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			password, err := tc.p.Generate()
			if err != nil {
				t.Fatalf("Generate() failed: %v", err)
			}

			if len(password) != int(tc.p.Length) {
				t.Errorf("Expected password to be %d characters long, got %d", tc.p.Length, len(password))
			}

			for _, f := range tc.p.Format {
				var characters string

				switch f {
				case 1:
					characters = lowerCase
				case 2:
					characters = upperCase
				case 3:
					characters = digit
				case 4:
					continue // Skip space (4) as we cannot guarantee that it won't be at the start or end of the password
				case 5:
					characters = special

				default:
					t.Errorf("Invalid format level, minimum is 1 and maximum 5, got %d", f)
				}

				if int(tc.p.Length) > len(tc.p.Format) {
					if !strings.ContainsAny(password, characters) {
						t.Errorf("Expected the password to contain at least one character of the level %d", f)
					}
				}
			}

			for _, inc := range tc.p.Include {
				// Skip space as we cannot guarantee that it won't be at the start or end of the password
				if !strings.ContainsAny(password, string(inc)) && inc != ' ' {
					t.Errorf("Character %q is not included", inc)
				}
			}

			for _, exc := range tc.p.Exclude {
				if strings.ContainsAny(password, string(exc)) {
					t.Errorf("Found undesired character: %q", exc)
				}
			}

			if !tc.p.Repeat && tc.p.Include == "" {
				uniques := make(map[rune]struct{}, tc.p.Length)

				for _, char := range password {
					if _, ok := uniques[char]; !ok {
						uniques[char] = struct{}{}
					}
				}

				if len(password) != len(uniques) {
					t.Errorf("Did not expect duplicated characters, got %d duplicates", len(password)-len(uniques))
				}
			}
		})
	}
}

func TestInvalidPassword(t *testing.T) {
	cases := map[string]*Password{
		"invalid length": {Length: 0},
		"invalid format": {
			Length: 5,
			Format: []int{0, 1, 4, 6},
		},
		"not enough characters to meet the length required": {
			Length: 30,
			Format: []int{1},
			Repeat: false,
		},
		"include characters also excluded": {
			Length:  7,
			Include: "?",
			Exclude: "?",
		},
		"include characters exceeds the length": {
			Length:  3,
			Include: "abcd",
		},
		"invalid include character": {
			Length:  5,
			Include: "éÄ",
		},
		"lowercase level is used and all the characters are excluded": {
			Length:  26,
			Format:  []int{1, 4},
			Exclude: lowerCase,
		},
		"uppercase level is used and all the characters are excluded": {
			Length:  26,
			Format:  []int{2, 4},
			Exclude: upperCase,
		},
		"digit level is used and all the characters are excluded": {
			Length:  10,
			Format:  []int{3, 4},
			Exclude: digit,
		},
		"space level is used and all the characters are excluded": {
			Length:  1,
			Format:  []int{4},
			Exclude: space,
		},
		"special level is used and all the characters are excluded": {
			Length:  20,
			Format:  []int{4, 5},
			Exclude: special,
		},
	}

	for k, tc := range cases {
		if _, err := tc.Generate(); err == nil {
			t.Errorf("Expected %q error, got nil", k)
		}
	}
}

func TestNewPassword(t *testing.T) {
	length := 15
	password, err := NewPassword(uint64(length), []int{1, 2, 3})
	if err != nil {
		t.Fatalf("NewPassword() failed: %v", err)
	}

	if len(password) != length {
		t.Errorf("Expected length to be %d but got %d", length, len(password))
	}

	if strings.ContainsAny(password, space+special) {
		t.Error("Found undesired characters")
	}
}

func TestInvalidNewPassword(t *testing.T) {
	cases := map[string]struct {
		length uint64
		format []int
	}{
		"invalid format": {length: 5, format: []int{0, 1, 4, 9}},
		"invalid length": {length: 0, format: []int{1}},
	}

	for k, tc := range cases {
		_, err := NewPassword(tc.length, tc.format)
		if err == nil {
			t.Errorf("Expected %q error, got nil", k)
		}
	}
}

func TestGeneratePool(t *testing.T) {
	cases := map[string]struct {
		fail     bool
		pool     string
		password *Password
	}{
		"All levels": {
			fail:     false,
			pool:     lowerCase + upperCase + digit + space + special,
			password: &Password{Format: []int{1, 2, 3, 4, 5}, Exclude: "aA"},
		},
		"Repeating levels": {
			fail:     false,
			pool:     lowerCase + upperCase + digit + space + special,
			password: &Password{Format: []int{1, 1, 2, 2, 3, 3, 4, 4, 5, 5}},
		},
		"First three levels": {
			fail:     true,
			pool:     lowerCase + upperCase + digit,
			password: &Password{Format: []int{1, 2, 3}, Exclude: "123"},
		},
		"Invalid levels": {
			fail:     true,
			pool:     "",
			password: &Password{Format: []int{0, 4, 6}},
		},
		"Default format": {
			fail:     false,
			pool:     lowerCase + upperCase + digit + space + special,
			password: &Password{},
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			levels := make(map[int]struct{})
			for _, l := range tc.password.Format {
				if l > 0 && l < 6 {
					levels[l] = struct{}{}
				}
			}

			tc.password.generatePool(levels)

			for _, e := range tc.password.Exclude {
				tc.pool = strings.ReplaceAll(tc.pool, string(e), "")
			}

			if !strings.ContainsAny(tc.password.pool, tc.pool) && tc.pool != "" {
				t.Error("Pool does not contain an expected character")
			}

			if strings.ContainsAny(tc.password.pool, tc.password.Exclude) {
				t.Errorf("Pool contains unexpected characters: %q", tc.password.Exclude)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	cases := []string{" trimSpacesX ", "admin123login"}

	p := &Password{Length: 13}
	p.pool = lowerCase + upperCase + digit

	for _, tc := range cases {
		got := p.sanitize(tc)

		if regexp.MustCompile(commonPatterns).MatchString(got) {
			t.Errorf("%q still contains common patterns", got)
		}

		start := got[0]
		end := got[len(got)-1]

		if start == ' ' || end == ' ' {
			t.Errorf("The password contains leading or traling spaces: %q", got)
		}

		if len(got) != int(p.Length) {
			t.Error("Trimmed spaces were not replaced with new characters")
		}

		if reflect.DeepEqual(tc, got) {
			t.Errorf("Did not shuffle. Before: %q, after: %q", tc, got)
		}
	}
}

func TestPasswordEntropy(t *testing.T) {
	p := &Password{
		Length:  20,
		Format:  []int{1, 2, 3, 4, 5},
		Exclude: "a1r/ö",
	}

	expected := 130.15589280397393

	got := p.Entropy()
	if got != expected {
		t.Errorf("Expected %f, got %f", expected, got)
	}
}
