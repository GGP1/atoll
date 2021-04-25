package atoll

import "testing"

func TestGetFuncName(t *testing.T) {
	cases := []struct {
		List     func(*Passphrase)
		Expected string
	}{
		{List: NoList, Expected: "NoList"},
		{List: WordList, Expected: "WordList"},
		{List: SyllableList, Expected: "SyllableList"},
	}

	for _, tc := range cases {
		got := getFuncName(tc.List)

		if got != tc.Expected {
			t.Errorf("Expected %q, got %q", tc.Expected, got)
		}
	}
}

func TestRemoveChar(t *testing.T) {
	t.Run("Present", func(t *testing.T) {
		pool := "12345a6789"
		expected := "123456789"
		got := removeChar(pool, "a")
		if got != expected {
			t.Errorf("Expected %q, got %q", expected, got)
		}
	})

	t.Run("Not present", func(t *testing.T) {
		pool := "abcdefgh"
		got := removeChar(pool, "1")
		if got != pool {
			t.Errorf("Expected %q, got %q", pool, got)
		}
	})
}

func TestShuffle(t *testing.T) {
	var p = "%A$Ks#a0t14|&23"
	password := []rune(p)

	shuffle(password)

	if p == string(password) {
		t.Errorf("Expected something different, got: %s", string(password))
	}
}
