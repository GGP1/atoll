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
				Levels:  []Level{Lowercase, Uppercase, Digit, Space, Special},
				Include: "kure ",
				Exclude: "ad",
				Repeat:  false,
			},
		},
		{
			desc: "Repeat",
			p: &Password{
				Length:  8,
				Levels:  []Level{Lowercase, Space},
				Include: "bee",
				Repeat:  true,
			},
		},
		{
			desc: "Length < levels",
			p: &Password{
				Length:  2,
				Levels:  []Level{Lowercase, Digit, Space, Special},
				Include: "!",
			},
		},
		{
			desc: "Verify levels",
			p: &Password{
				Length:  35,
				Levels:  []Level{Lowercase, Uppercase, Digit, Space, Special},
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

			for i, lvl := range tc.p.Levels {
				if lvl == Space {
					continue
				}

				if int(tc.p.Length) > len(tc.p.Levels) {
					if !strings.ContainsAny(password, string(lvl)) {
						t.Errorf("Expected the password to contain at least one character of the level %d", i)
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
		"invalid levels": {Length: 10},
		"empty level":    {Length: 3, Levels: []Level{Level("")}},
		"not enough characters to meet the length required": {
			Length: 30,
			Levels: []Level{Lowercase},
			Repeat: false,
		},
		"include characters also excluded": {
			Length:  7,
			Levels:  []Level{Digit},
			Include: "?",
			Exclude: "?",
		},
		"include characters exceeds the length": {
			Length:  3,
			Levels:  []Level{Digit},
			Include: "abcd",
		},
		"invalid include character": {
			Length:  5,
			Levels:  []Level{Digit},
			Include: "éÄ",
		},
		"lowercase level chars are excluded": {
			Length:  26,
			Levels:  []Level{Lowercase, Space},
			Exclude: string(Lowercase),
		},
		"uppercase level chars are excluded": {
			Length:  26,
			Levels:  []Level{Uppercase, Space},
			Exclude: string(Uppercase),
		},
		"digit level chars are excluded": {
			Length:  10,
			Levels:  []Level{Lowercase, Digit, Space},
			Exclude: string(Digit) + "aB",
		},
		"space level chars are excluded": {
			Length:  1,
			Levels:  []Level{Space},
			Exclude: string(Space) + "/",
		},
		"special level chars are excluded": {
			Length:  20,
			Levels:  []Level{Space, Special},
			Exclude: string(Special),
		},
		"custom level chars are excluded": {
			Length:  12,
			Levels:  []Level{Level("test")},
			Exclude: "test",
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
	password, err := NewPassword(uint64(length), []Level{Lowercase, Uppercase, Digit})
	if err != nil {
		t.Fatalf("NewPassword() failed: %v", err)
	}

	if len(password) != length {
		t.Errorf("Expected length to be %d but got %d", length, len(password))
	}

	if strings.ContainsAny(password, string(Space)+string(Special)) {
		t.Error("Found undesired characters")
	}
}

func TestInvalidNewPassword(t *testing.T) {
	cases := map[string]struct {
		length uint64
		levels []Level
	}{
		"invalid length": {length: 0, levels: []Level{Lowercase}},
	}

	for k, tc := range cases {
		if _, err := NewPassword(tc.length, tc.levels); err == nil {
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
			pool:     string(Lowercase + Uppercase + Digit + Space + Special),
			password: &Password{Levels: []Level{Lowercase, Uppercase, Digit, Space, Special}, Exclude: "aA"},
		},
		"Repeating levels": {
			fail:     false,
			pool:     string(Lowercase) + string(Digit),
			password: &Password{Levels: []Level{Lowercase, Lowercase, Digit, Digit}},
		},
		"First three levels": {
			fail:     true,
			pool:     string(Lowercase) + string(Uppercase) + string(Digit),
			password: &Password{Levels: []Level{Lowercase, Uppercase, Digit}, Exclude: "123"},
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			tc.password.generatePool()

			for _, e := range tc.password.Exclude {
				tc.pool = strings.ReplaceAll(tc.pool, string(e), "")
			}

			if !strings.ContainsAny(tc.password.pool, tc.pool) && tc.pool != "" {
				t.Error("Pool does not contain an expected character")
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	cases := []string{" trimSpacesX ", "admin123login"}

	p := &Password{Length: 13}
	p.pool = string(Lowercase) + string(Uppercase) + string(Digit)

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
		Levels:  []Level{Lowercase, Uppercase, Digit, Space, Special},
		Exclude: "a1r/ö",
	}

	expected := 136.65780028329485

	got := p.Entropy()
	if got != expected {
		t.Errorf("Expected %f, got %f", expected, got)
	}
}
