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

func TestShuffle(t *testing.T) {
	var p string = "%A$Ks#a0t14|&23"
	password := []rune(p)

	shuffle(password)

	if p == string(password) {
		t.Errorf("Expected something different, got: %s", string(password))
	}
}
