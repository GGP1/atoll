package atoll

import (
	"testing"
)

func TestGetFuncName(t *testing.T) {
	cases := []struct {
		List     func(p *Passphrase, length int)
		Expected string
	}{
		{List: NoList, Expected: "NoList"},
		{List: WordList, Expected: "WordList"},
		{List: SyllableList, Expected: "SyllableList"},
		{List: nil, Expected: ""},
	}

	for _, tc := range cases {
		got := getFuncName(tc.List)

		if got != tc.Expected {
			t.Errorf("Expected %q, got %q", tc.Expected, got)
		}
	}
}

func TestShuffle(t *testing.T) {
	p := "%A$Ks#a0t14|&23"
	password := []byte(p)

	if _, err := shuffle(password); err != nil {
		t.Fatalf("shuffle() failed: %v", err)
	}

	if p == string(password) {
		t.Errorf("Expected something different, got: %s", password)
	}
}

func TestRandInt(t *testing.T) {
	for _, max := range []int{0, -1} {
		if _, err := randInt(max); err == nil {
			t.Errorf("Expected an error with max %d, got nil", max)
		}
	}

	for i := 0; i < 100; i++ {
		n, err := randInt(5)
		if err != nil {
			t.Fatalf("randInt() failed: %v", err)
		}

		if n < 0 || n > 4 {
			t.Errorf("Expected a number in [0, 5), got %d", n)
		}
	}
}
