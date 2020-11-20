package atoll_test

import (
	"fmt"
	"log"

	"github.com/GGP1/atoll"
)

func ExamplePassword() {
	p := &atoll.Password{
		Length:  22,
		Format:  []uint8{1, 2, 3, 4, 5, 6},
		Include: "1+=Á",
		Exclude: "&r/Ë",
		Repeat:  false,
	}

	password, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatalf("Couldn't generate the password: %v", err)
	}

	fmt.Println(password)
	// Example output:
	// H1k+6R0tMU3=aFlh2DCy5O
}

func ExampleNewPassword() {
	password, err := atoll.NewPassword(16, []uint8{1, 2, 3, 4, 5})
	if err != nil {
		log.Fatalf("Failed creating password: %v", err)
	}

	fmt.Println(password)
	// Example output:
	// ?{{5Rt%r3OrE}7?z
}
func ExamplePassphrase() {
	p := &atoll.Passphrase{
		Length:    8,
		Separator: "&",
		List:      atoll.WordList,
		Include:   []string{"atoll"},
		Exclude:   []string{"watermelon"},
	}

	passphrase, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatalf("Couldn't generate the password: %v", err)
	}

	fmt.Println(passphrase)
	// Example output:
	// eremite&align&coward&casing&atoll&maximum&user&adult
}

func ExampleNewPassphrase() {
	passphrase, err := atoll.NewPassphrase(5, atoll.NoList)
	if err != nil {
		log.Fatalf("Failed creating passphrase: %v", err)
	}

	fmt.Println(passphrase)
	// Example output:
	// ynuafnezm hvoq asruso jvoe psiro
}
