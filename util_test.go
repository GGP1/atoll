package atoll

import (
	"testing"
)

func TestBufferPool(t *testing.T) {
	text := "bufferpool test"
	buf := getBuf()
	buf.WriteString(text)
	if buf.String() != text {
		t.Error("The buffer contains erroneous text")
	}
	putBuf(buf)
	if buf.Len() != 0 {
		t.Error("The buffer is not empty")
	}
}

func TestGetFuncName(t *testing.T) {
	cases := []struct {
		List     func(p *Passphrase, length int)
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
	p := "%A$Ks#a0t14|&23"
	password := []byte(p)

	shuffle(password)

	if p == string(password) {
		t.Errorf("Expected something different, got: %s", password)
	}
}
