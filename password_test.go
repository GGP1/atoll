package atoll

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	cases := []*Password{
		{Length: 14, Format: []uint8{1, 5, 6}, Include: "kure", Exclude: "adé", Repeat: false},
		{Length: 8, Format: []uint8{1, 4}, Include: "á", Repeat: true},
		{Length: 40, Format: []uint8{1, 2, 3}, Include: "231", Repeat: false},
		{Length: 20},
	}

	for _, tc := range cases {
		password, err := NewSecret(tc)
		if err != nil {
			t.Errorf("NewSecret() failed: %v", err)
		}

		if len([]rune(password)) != int(tc.Length) {
			t.Errorf("Expected to be %d characters long, got %d", tc.Length, len(password))
		}

		for _, f := range tc.Format {
			var min uint8 = 1
			var max uint8 = 6
			if f < min || f > max {
				t.Errorf("Invalid format level, minimum is %d and maximum %d, got %d", min, max, f)
			}
		}

		for _, inc := range tc.Include {
			if !strings.ContainsAny(password, string(inc)) {
				t.Errorf("Character %q is not included", inc)
			}
		}

		for _, exc := range tc.Exclude {
			if strings.ContainsAny(password, string(exc)) {
				t.Errorf("Found undesired character: %q", exc)
			}
		}

		if !tc.Repeat && tc.Include == "" {
			uniques := make(map[rune]struct{}, tc.Length)

			for _, char := range password {
				if _, ok := uniques[char]; !ok {
					uniques[char] = struct{}{}
				}
			}

			if len(password) != len(uniques) {
				diff := len(password) - len(uniques)
				t.Errorf("Did not expect duplicated characters, got %d duplicates", diff)
			}
		}
	}
}
func TestInvalidPassword(t *testing.T) {
	cases := map[string]*Password{
		"invalid length": {Length: 0},
		"invalid format": {Length: 5, Format: []uint8{0, 1, 4, 6}},
		"not enough characters to meet the length required": {Length: 30, Format: []uint8{1}, Repeat: false},
		"include characters also excluded":                  {Length: 7, Include: "?", Exclude: "?"},
		"include characters exceeds the length":             {Length: 3, Include: "abcd"},
	}

	for k, tc := range cases {
		_, err := NewSecret(tc)
		if err == nil {
			t.Errorf("Expected %q error, got nil", k)
		}
	}
}

func TestNewPassword(t *testing.T) {
	length := 15
	password, err := NewPassword(uint64(length), []uint8{1, 2, 3, 6})
	if err != nil {
		t.Fatalf("NewPassword() failed: %v", err)
	}

	if len([]rune(password)) != length {
		t.Errorf("Expected length to be %d but got %d", length, len(password))
	}

	if strings.ContainsAny(password, space+special) {
		t.Error("Found undesired characters")
	}
}

func TestInvalidNewPassword(t *testing.T) {
	cases := map[string]struct {
		length uint64
		format []uint8
	}{
		"invalid format": {length: 5, format: []uint8{0, 1, 4, 9}},
		"invalid length": {length: 0, format: []uint8{1}},
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
		Fail     bool
		Pool     string
		Password *Password
	}{
		"All levels": {
			Fail:     false,
			Pool:     lowerCase + upperCase + digit + space + special,
			Password: &Password{Format: []uint8{1, 2, 3, 4, 5, 6}, Exclude: "aA"},
		},
		"Repeating levels": {
			Fail:     false,
			Pool:     lowerCase + upperCase + digit + space + special,
			Password: &Password{Format: []uint8{1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6}},
		},
		"First three levels": {
			Fail:     true,
			Pool:     lowerCase + upperCase + digit,
			Password: &Password{Format: []uint8{1, 2, 3}, Exclude: "123"},
		},
		"Invalid levels": {
			Fail:     true,
			Pool:     "",
			Password: &Password{Format: []uint8{0, 4, 7}},
		},
		"Default format": {
			Fail:     false,
			Pool:     lowerCase + upperCase + digit + space + special,
			Password: &Password{},
		},
	}

	for k, tc := range cases {
		pool, err := tc.Password.generatePool()
		if err != nil && !tc.Fail {
			t.Errorf("%s: failed generating the pool: %v", k, err)
		}

		for _, e := range tc.Password.Exclude {
			tc.Pool = strings.Replace(tc.Pool, string(e), "", -1)
		}

		if !strings.ContainsAny(string(pool), tc.Pool) && tc.Pool != "" {
			t.Errorf("%s: the pool doesn't contain an expected character", k)
		}

		if strings.ContainsAny(string(pool), tc.Password.Exclude) {
			t.Errorf("%s: pool contains unexpected characters: %q", k, tc.Password.Exclude)
		}
	}
}

func TestVerify(t *testing.T) {
	cases := [][]rune{
		[]rune(" trimSpacesX "),
		[]rune("admin123login"),
	}

	p := &Password{Length: 13}
	pool := []rune(lowerCase + upperCase + digit)

	for _, tc := range cases {
		got := p.verify(tc, pool)

		if regexp.MustCompile(commonPatterns).MatchString(string(tc)) {
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

func TestShuffle(t *testing.T) {
	var p string = "%A$Ks#a0t14|&23"
	password := []rune(p)

	shuffle(password)

	if p == string(password) {
		t.Errorf("Expected something different, got: %s", string(password))
	}
}
