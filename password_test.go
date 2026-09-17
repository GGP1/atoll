package atoll

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	cases := []struct {
		p    *Password
		desc string
	}{
		{
			desc: "Test all",
			p: &Password{
				Length:  14,
				Levels:  []Level{Lower, Upper, Digit, Space, Special},
				Include: "kure ",
				Exclude: "ad",
				Repeat:  false,
			},
		},
		{
			desc: "Repeat",
			p: &Password{
				Length:  8,
				Levels:  []Level{Lower, Space},
				Include: "bee",
				Repeat:  true,
			},
		},
		{
			desc: "Length < levels",
			p: &Password{
				Length:  2,
				Levels:  []Level{Lower, Digit, Space, Special},
				Include: "!",
			},
		},
		{
			desc: "Verify levels",
			p: &Password{
				Length:  35,
				Levels:  []Level{Lower, Upper, Digit, Space, Special},
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
					if !bytes.ContainsAny(password, string(lvl)) {
						t.Errorf("Expected the password to contain at least one character of the level %d", i)
					}
				}
			}

			for _, inc := range tc.p.Include {
				// Skip space as we cannot guarantee that it won't be at the start or end of the password
				if !bytes.ContainsRune(password, inc) && inc != ' ' {
					t.Errorf("Character %q is not included", inc)
				}
			}

			for _, exc := range tc.p.Exclude {
				if bytes.ContainsRune(password, exc) {
					t.Errorf("Found undesired character: %q", exc)
				}
			}

			if !tc.p.Repeat && tc.p.Include == "" {
				uniques := make(map[byte]struct{}, tc.p.Length)

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
			Levels: []Level{Lower},
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
			Levels:  []Level{Lower, Space},
			Exclude: string(Lower),
		},
		"uppercase level chars are excluded": {
			Length:  26,
			Levels:  []Level{Upper, Space},
			Exclude: string(Upper),
		},
		"digit level chars are excluded": {
			Length:  10,
			Levels:  []Level{Lower, Digit, Space},
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

// TestPasswordConcurrency makes sure that passwords generated concurrently don't share
// any memory, run it with the race detector enabled.
func TestPasswordConcurrency(t *testing.T) {
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := 0; j < 50; j++ {
				password, err := NewPassword(12, []Level{Lower, Upper, Digit, Special})
				if err != nil {
					t.Error(err)
					return
				}

				if len(password) != 12 {
					t.Errorf("Expected a password of 12 characters, got %d", len(password))
					return
				}

				if bytes.IndexByte(password, 0) != -1 {
					t.Errorf("The password contains characters outside the pool: %q", password)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestPasswordTermination covers the cases that used to loop forever or panic.
func TestPasswordTermination(t *testing.T) {
	cases := map[string]*Password{
		"duplicated excluded characters": {
			Length:  2,
			Levels:  []Level{Level("ab")},
			Exclude: "aab",
			Repeat:  true,
		},
		"included characters cover a level": {
			Length:  11,
			Levels:  []Level{Digit},
			Include: "0123456789",
			Repeat:  false,
		},
		"length higher than the real capacity": {
			Length:  27,
			Levels:  []Level{Lower},
			Include: "abcdefghijklmnopqrs",
			Repeat:  false,
		},
		"pool of spaces only": {
			Length: 1,
			Levels: []Level{Space},
			Repeat: false,
		},
		"included character repeated without repetition": {
			Length:  8,
			Levels:  []Level{Lower},
			Include: "aa",
			Repeat:  false,
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			done := make(chan struct{})

			go func() {
				defer close(done)

				if _, err := tc.Generate(); err == nil {
					t.Errorf("Expected %q error, got nil", k)
				}
			}()

			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("Generate() did not terminate")
			}
		})
	}
}

// TestPasswordExactCapacity uses every single character of the pool, the space trimmed
// by the sanitizer may leave no character to replace it with.
func TestPasswordExactCapacity(t *testing.T) {
	for i := 0; i < 50; i++ {
		p := &Password{
			Length: uint64(len(Lower) + len(Space)),
			Levels: []Level{Lower, Space},
			Repeat: false,
		}

		password, err := p.Generate()
		if err != nil {
			continue
		}

		if len(password) != int(p.Length) {
			t.Fatalf("Expected a password of %d characters, got %d: %q", p.Length, len(password), password)
		}
	}
}

// TestPasswordLevelSatisfiedByInclude verifies that a level covered by the characters
// to include doesn't make the generation fail.
func TestPasswordLevelSatisfiedByInclude(t *testing.T) {
	p := &Password{
		Length:  12,
		Levels:  []Level{Digit, Lower},
		Include: "0123456789",
		Repeat:  false,
	}

	password, err := p.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	if len(password) != int(p.Length) {
		t.Errorf("Expected a password of %d characters, got %d", p.Length, len(password))
	}

	if !bytes.ContainsAny(password, string(Lower)) {
		t.Errorf("Expected the password %q to contain a lowercase character", password)
	}
}

func TestNewPassword(t *testing.T) {
	length := 15
	password, err := NewPassword(uint64(length), []Level{Lower, Upper, Digit})
	if err != nil {
		t.Fatalf("NewPassword() failed: %v", err)
	}

	if len(password) != length {
		t.Errorf("Expected length to be %d but got %d", length, len(password))
	}

	if bytes.ContainsAny(password, string(Space)+string(Special)) {
		t.Error("Found undesired characters")
	}
}

func TestInvalidNewPassword(t *testing.T) {
	cases := map[string]struct {
		levels []Level
		length uint64
	}{
		"invalid length": {length: 0, levels: []Level{Lower}},
	}

	for k, tc := range cases {
		if _, err := NewPassword(tc.length, tc.levels); err == nil {
			t.Errorf("Expected %q error, got nil", k)
		}
	}
}

func TestGeneratePool(t *testing.T) {
	cases := map[string]struct {
		password *Password
		pool     string
		fail     bool
	}{
		"All levels": {
			fail:     false,
			pool:     string(Lower + Upper + Digit + Space + Special),
			password: &Password{Levels: []Level{Lower, Upper, Digit, Space, Special}, Exclude: "aA"},
		},
		"Repeating levels": {
			fail:     false,
			pool:     string(Lower) + string(Digit),
			password: &Password{Levels: []Level{Lower, Lower, Digit, Digit}},
		},
		"First three levels": {
			fail:     true,
			pool:     string(Lower) + string(Upper) + string(Digit),
			password: &Password{Levels: []Level{Lower, Upper, Digit}, Exclude: "123"},
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			tc.password.generatePool()

			for _, e := range tc.password.Exclude {
				tc.pool = strings.ReplaceAll(tc.pool, string(e), "")
			}

			if !bytes.ContainsAny(tc.password.pool, tc.pool) && tc.pool != "" {
				t.Error("Pool does not contain an expected character")
			}
		})
	}
}

func TestRandInsert(t *testing.T) {
	p := &Password{Length: 13, Repeat: false, pool: []byte("ab")}
	char1 := 'a'
	char2 := 'b'

	password, err := p.randInsert([]byte{}, byte(char1))
	if err != nil {
		t.Fatalf("randInsert() failed: %v", err)
	}
	password, err = p.randInsert(password, byte(char2))
	if err != nil {
		t.Fatalf("randInsert() failed: %v", err)
	}
	pwd := string(password)

	if pwd != "ab" && pwd != "ba" {
		t.Errorf("Expected \"ab\"/\"ba\" and got %q", pwd)
	}
	if bytes.ContainsAny(p.pool, "ab") {
		t.Errorf("Failed removing characters from the pool")
	}
}

func TestSanitize(t *testing.T) {
	cases := [][]byte{[]byte(" trimSpacesX "), []byte("admin123login")}

	p := &Password{Length: 13}
	p.pool = []byte(string(Lower) + string(Upper) + string(Digit))

	for _, tc := range cases {
		got, err := p.sanitize(tc)
		if err != nil {
			t.Fatalf("sanitize() failed: %v", err)
		}

		if commonPatterns.Match(got) {
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
	}
}

func TestPasswordEntropy(t *testing.T) {
	cases := []struct {
		p        *Password
		desc     string
		expected float64
	}{
		{
			desc: "Repetition",
			p: &Password{
				Length:  20,
				Levels:  []Level{Lower, Upper, Digit, Space, Special},
				Exclude: "a1r/ö",
				Repeat:  true,
			},
			// 20 characters taken from a pool of 91
			expected: 130.15589280397393,
		},
		{
			desc: "Without repetition",
			p: &Password{
				Length:  20,
				Levels:  []Level{Lower, Upper, Digit, Space, Special},
				Exclude: "a1r/ö",
			},
			// 20 characters sampled without replacement from a pool of 91
			expected: 126.90201756696135,
		},
		{
			desc: "Included characters are known",
			p: &Password{
				Length:  16,
				Levels:  []Level{Lower, Upper, Digit},
				Include: "a&1",
				Repeat:  true,
			},
			// 13 characters taken from a pool of 62, "a&1" adds nothing
			expected: 13 * math.Log2(62),
		},
		{
			desc: "Only included characters",
			p: &Password{
				Length:  3,
				Levels:  []Level{Lower},
				Include: "abc",
				Repeat:  true,
			},
			expected: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := tc.p.Entropy()
			if got != tc.expected {
				t.Errorf("Expected %f, got %f", tc.expected, got)
			}
		})
	}
}
