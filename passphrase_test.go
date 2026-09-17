package atoll

import (
	"bytes"
	"math"
	"sync"
	"testing"
)

func TestPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"No list": {
			Length:    14,
			Separator: "/",
			List:      NoList,
		},
		"Word list": {
			Length:    4,
			Separator: "",
			Include:   []string{"apple", "orange", "watermelon"},
			List:      WordList,
		},
		"Syllable list": {
			Length:    6,
			Separator: "==",
			Include:   []string{"test"},
			List:      SyllableList,
		},
		"Default values": {
			Length:  10,
			Include: []string{"background"},
			Exclude: []string{"unit"},
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			passphrase, err := tc.Generate()
			if err != nil {
				t.Fatalf("Generate() failed: %v", err)
			}

			words := bytes.Split(passphrase, []byte(tc.Separator))
			if len(words) != int(tc.Length) {
				t.Errorf("Expected %d words, got %d", tc.Length, len(words))
			}

			if !bytes.Contains(passphrase, []byte(tc.Separator)) {
				t.Errorf("The separator %q is not used", tc.Separator)
			}

			for _, inc := range tc.Include {
				if !bytes.ContainsAny(passphrase, inc) {
					t.Errorf("Expected %q to be included", inc)
				}
			}

			for _, w := range words {
				for _, exc := range tc.Exclude {
					if exc == string(w) {
						t.Errorf("Expected %q to be excluded", exc)
					}
				}
			}
		})
	}
}

func TestInvalidPassphrase(t *testing.T) {
	cases := map[string]*Passphrase{
		"invalid length":               {Length: 0},
		"invalid separator":            {Length: 5, Separator: "¿"},
		"len(Include) > Length":        {Length: 2, Include: []string{"must", "throw", "error"}},
		"included words also excluded": {Length: 2, Include: []string{"Go"}, Exclude: []string{"Go"}},
		"invalid included word":        {Length: 7, Include: []string{"ínvalid"}},
	}

	for k, tc := range cases {
		if _, err := tc.Generate(); err == nil {
			t.Errorf("Expected %q error, got nil", k)
		}
	}
}

func TestNewPassphrase(t *testing.T) {
	length := 5
	passphrase, err := NewPassphrase(uint64(length), NoList)
	if err != nil {
		t.Errorf("NewPassphrase() failed: %v", err)
	}

	words := bytes.Split(passphrase, []byte(" "))
	got := len(words)

	if got != length {
		t.Errorf("Expected %d words, got %d", length, got)
	}
}

func TestInvalidNewPassphrase(t *testing.T) {
	_, err := NewPassphrase(0, WordList)
	if err == nil {
		t.Error("Expected \"invalid length\" error, got nil")
	}
}

func TestExcludeWords(t *testing.T) {
	cases := map[string]*Passphrase{
		"No list": {
			words:     [][]byte{[]byte("cow"), []byte("horse"), []byte("bee")},
			Separator: " ",
			Exclude:   []string{"cow", "horse", "beer"},
			List:      NoList,
		},
		"Word list": {
			words:     [][]byte{[]byte("about"), []byte("abysmal"), []byte("accurate")},
			Separator: " ",
			Exclude:   []string{"about"},
			List:      WordList,
		},
		"Syllable list": {
			words:     [][]byte{[]byte("alt"), []byte("bet"), []byte("bang flux")},
			Separator: " ",
			Exclude:   []string{"alt", "flux"},
			List:      SyllableList,
		},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			if err := tc.excludeWords(); err != nil {
				t.Fatalf("excludeWords() failed: %v", err)
			}

			for _, exc := range tc.Exclude {
				for _, word := range tc.words {
					if exc == string(word) {
						t.Errorf("Found undesired word %q", exc)
					}
				}
			}
		})
	}
}

// TestPassphraseConcurrency makes sure that passphrases generated concurrently don't
// share any memory, run it with the race detector enabled.
func TestPassphraseConcurrency(t *testing.T) {
	var wg sync.WaitGroup

	for _, l := range []list{NoList, WordList, SyllableList} {
		for i := 0; i < 4; i++ {
			wg.Add(1)

			go func(l list) {
				defer wg.Done()

				for j := 0; j < 25; j++ {
					passphrase, err := NewPassphrase(5, l)
					if err != nil {
						t.Error(err)
						return
					}

					if bytes.IndexByte(passphrase, 0) != -1 {
						t.Errorf("The passphrase contains wiped words: %q", passphrase)
						return
					}
				}
			}(l)
		}
	}

	wg.Wait()
}

// TestExcludeWordsCustomList makes sure that excluded words are replaced when the list
// used is not one of the built-in ones.
func TestExcludeWordsCustomList(t *testing.T) {
	calls := 0
	list := func(p *Passphrase, length int) {
		for i := 0; i < length; i++ {
			calls++
			if calls == 1 {
				p.words[i] = []byte("bad")
				continue
			}

			p.words[i] = []byte("good")
		}
	}

	p := &Passphrase{
		Length:    2,
		Separator: " ",
		List:      list,
		Exclude:   []string{"bad"},
	}

	passphrase, err := p.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	if bytes.Contains(passphrase, []byte("bad")) {
		t.Errorf("Found undesired word in %q", passphrase)
	}
}

// TestExcludeWordsExhausted verifies that excluding every word of the list returns an
// error instead of recursing/looping forever.
func TestExcludeWordsExhausted(t *testing.T) {
	list := func(p *Passphrase, length int) {
		for i := 0; i < length; i++ {
			p.words[i] = []byte("only")
		}
	}

	p := &Passphrase{
		Length:  3,
		List:    list,
		Exclude: []string{"only"},
	}

	if _, err := p.Generate(); err == nil {
		t.Error("Expected an error, got nil")
	}
}

// TestListsAreNotMutated makes sure that the word/syllable lists aren't modified when
// the words of a generated passphrase are wiped.
func TestListsAreNotMutated(t *testing.T) {
	cases := map[string]struct {
		list  list
		words [][]byte
	}{
		"Word list":     {list: WordList, words: wordList},
		"Syllable list": {list: SyllableList, words: syllableList},
	}

	for k, tc := range cases {
		t.Run(k, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				if _, err := NewPassphrase(6, tc.list); err != nil {
					t.Fatalf("NewPassphrase() failed: %v", err)
				}
			}

			for _, word := range tc.words {
				if bytes.IndexByte(word, 0) != -1 {
					t.Fatalf("The list was modified, it contains the word %q", word)
				}
			}
		})
	}
}

func TestPassphraseEntropy(t *testing.T) {
	cases := []struct {
		list     list
		desc     string
		expected float64
	}{
		{
			desc: "No list",
			list: NoList,
		},
		{
			desc: "Word list",
			list: WordList,
			// 3 words (the included one is known) out of a list of 18325
			expected: 3 * math.Log2(18325),
		},
		{
			desc: "Syllable list",
			list: SyllableList,
			// 3 syllables (the included one is known) out of a list of 10129
			expected: 3 * math.Log2(10129),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			p := &Passphrase{
				Length:    4,
				List:      tc.list,
				Separator: "/",
				Include:   []string{"atoll"},
			}

			if _, err := p.Generate(); err != nil {
				t.Fatalf("Generate() failed: %v", err)
			}

			// NoList entropy changes everytime as it generates random words
			if getFuncName(tc.list) == noListType {
				// The separator isn't part of the secret and the included word is known
				letters := len(bytes.Join(p.words, []byte(""))) - len("atoll")
				tc.expected = float64(letters) * letterEntropy
			}

			got := p.Entropy()
			if got != tc.expected {
				t.Errorf("Expected %f, got %f", tc.expected, got)
			}
		})
	}
}

func TestPassphraseEntropyCustomList(t *testing.T) {
	p := &Passphrase{
		Length: 4,
		List:   func(p *Passphrase, length int) {},
	}

	// The pool of words of a custom list cannot be determined
	if got := p.Entropy(); got != 0 {
		t.Errorf("Expected 0, got %f", got)
	}
}

func TestPassphraseEntropyNoSecret(t *testing.T) {
	p := &Passphrase{
		Length:    7,
		List:      NoList,
		Separator: "/",
	}

	var expected float64
	got := p.Entropy()
	if got != expected {
		t.Errorf("Expected %f, got %f", expected, got)
	}
}
