package atoll

import (
	"testing"
)

var password = &Password{
	Length:  15,
	Format:  []int{1, 2, 3, 4, 5},
	Include: "bench",
	Exclude: "mark1234T=%",
	Repeat:  true,
}

func BenchmarkPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(password)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkNewPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPassword(password.Length, password.Format)
		if err != nil {
			b.Error(err)
		}
	}
}

var passphrase = &Passphrase{
	Length:    6,
	Separator: "-",
	Include:   []string{"enjoy"},
	Exclude:   []string{"play"},
}

func BenchmarkNewPassphrase(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPassphrase(passphrase.Length, NoList)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkPassphrase_NoList(b *testing.B) {
	passphrase.List = NoList
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(passphrase)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkPassphrase_WordList(b *testing.B) {
	passphrase.List = WordList
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(passphrase)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkPassphrase_SyllableList(b *testing.B) {
	passphrase.List = SyllableList
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(passphrase)
		if err != nil {
			b.Error(err)
		}
	}
}
