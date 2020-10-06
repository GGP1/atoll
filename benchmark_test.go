package atoll

import "testing"

var password = &Password{
	Length:  15,
	Format:  []int{1, 2, 3, 4, 5},
	Include: "bench",
	Exclude: "mark",
	Repeat:  true,
}

func BenchmarkNewPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPassword(15, []int{1, 2, 3, 4, 5}, "bench", "mark", true)
		if err != nil {
			b.Error("Generating password failed")
		}
	}
}

func BenchmarkPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := password.Generate(); err != nil {
			b.Error("Generating password failed")
		}
	}
}

var passphrase = &Passphrase{
	Length:    6,
	Separator: "-",
	Include:   []string{"enjoy"},
	Exclude:   []string{"ban"},
}

func BenchmarkNewPassphrase(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPassphrase(6, "-", []string{"enjoy"}, []string{"ban"}, NoList)
		if err != nil {
			b.Error("Generating password failed")
		}
	}
}

func BenchmarkPassphrase_NoList(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := passphrase.Generate(NoList); err != nil {
			b.Error("Generating passphrase failed")
		}
	}
}

func BenchmarkPassphrase_WordList(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := passphrase.Generate(WordList); err != nil {
			b.Error("Generating passphrase failed")
		}
	}
}

func BenchmarkPassphrase_SyllableList(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := passphrase.Generate(SyllableList); err != nil {
			b.Error("Generating passphrase failed")
		}
	}
}
