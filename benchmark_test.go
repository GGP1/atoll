package atoll_test

import (
	"testing"

	"github.com/GGP1/atoll"
)

var password = &atoll.Password{
	Length:  15,
	Format:  []int{1, 2, 3, 4, 5},
	Include: "bench",
	Exclude: "mark",
	Repeat:  true,
}

func BenchmarkNewSecret_Password(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := atoll.NewSecret(password); err != nil {
			b.Error("Failed generating password")
		}
	}
}

func BenchmarkNewPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := atoll.NewPassword(15, []int{1, 2, 3, 4, 5})
		if err != nil {
			b.Error("Failed generating password")
		}
	}
}

func BenchmarkPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := password.Generate(); err != nil {
			b.Error("Failed generating password")
		}
	}
}

var passphrase = &atoll.Passphrase{
	Length:    6,
	Separator: "-",
	Include:   []string{"enjoy"},
	Exclude:   []string{"ban"},
}

func BenchmarkNewSecret_Passphrase(b *testing.B) {
	passphrase.List = atoll.NoList
	for i := 0; i < b.N; i++ {
		if err := atoll.NewSecret(passphrase); err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkNewPassphrase(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := atoll.NewPassphrase(6, atoll.NoList)
		if err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkPassphrase_NoList(b *testing.B) {
	passphrase.List = atoll.NoList
	for i := 0; i < b.N; i++ {
		if err := passphrase.Generate(); err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkPassphrase_WordList(b *testing.B) {
	passphrase.List = atoll.WordList
	for i := 0; i < b.N; i++ {
		if err := passphrase.Generate(); err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}

func BenchmarkPassphrase_SyllableList(b *testing.B) {
	passphrase.List = atoll.SyllableList
	for i := 0; i < b.N; i++ {
		if err := passphrase.Generate(); err != nil {
			b.Error("Failed generating passphrase")
		}
	}
}
