package atoll

import (
	"testing"
)

var password = &Password{
	Length:  15,
	Format:  []uint8{1, 2, 3, 4, 5, 6},
	Include: "bénch",
	Exclude: "mÄrk",
	Repeat:  true,
}

func BenchmarkPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(password)
		if err != nil {
			b.Error("Failed generating password")
		}
	}
}

func BenchmarkNewPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPassword(15, []uint8{1, 2, 3, 4, 5, 6})
		if err != nil {
			b.Error("Failed generating password")
		}
	}
}

var passphrase = &Passphrase{
	Length:    6,
	Separator: "-",
	Include:   []string{"enjóy"},
	Exclude:   []string{"play¡"},
}

func BenchmarkNewPassphrase(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPassphrase(6, NoList)
		if err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkPassphrase_NoList(b *testing.B) {
	passphrase.List = NoList
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(passphrase)
		if err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkPassphrase_WordList(b *testing.B) {
	passphrase.List = WordList
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(passphrase)
		if err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkPassphrase_SyllableList(b *testing.B) {
	passphrase.List = SyllableList
	for i := 0; i < b.N; i++ {
		_, err := NewSecret(passphrase)
		if err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}
