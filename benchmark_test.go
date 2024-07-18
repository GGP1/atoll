package atoll

import (
	mrand "math/rand/v2"
	"testing"
)

var password = &Password{
	Length:  15,
	Levels:  []Level{Lower, Upper, Digit, Space, Special},
	Include: "bench",
	Exclude: "mark1234T=%",
	Repeat:  false,
}

func BenchmarkPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewSecret(password); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkNewPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := NewPassword(password.Length, password.Levels); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSecretFromString(b *testing.B) {
	b.StopTimer()

	// Preload strings
	strs := make([]string, b.N)
	chars := Lower + Upper + Digit + Space + Special

	for i := 0; i < b.N; i++ {
		buf := make([]byte, 24)
		for j := 0; j < 24; j++ {
			buf[j] = chars[mrand.IntN(len(chars))]
		}
		strs[i] = string(buf)
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_ = SecretFromString(strs[i])
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
		if _, err := NewPassphrase(passphrase.Length, NoList); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkPassphrase_NoList(b *testing.B) {
	passphrase.List = NoList
	for i := 0; i < b.N; i++ {
		if _, err := NewSecret(passphrase); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkPassphrase_WordList(b *testing.B) {
	passphrase.List = WordList
	for i := 0; i < b.N; i++ {
		if _, err := NewSecret(passphrase); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkPassphrase_SyllableList(b *testing.B) {
	passphrase.List = SyllableList
	for i := 0; i < b.N; i++ {
		if _, err := NewSecret(passphrase); err != nil {
			b.Error(err)
		}
	}
}
