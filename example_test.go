package atoll_test

import (
	"fmt"
	"log"

	"github.com/GGP1/atoll"
)

func ExamplePassword() {
	p := &atoll.Password{
		Length:  22,
		Levels:  []atoll.Level{atoll.Lowercase, atoll.Uppercase, atoll.Special},
		Include: "1+=g ",
		Exclude: "&r/ty",
		Repeat:  false,
	}

	password, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(password)
	// Example output:
	// AE8f@,1^P_Ws=c!ho`T{Á+
}

func ExampleNewPassword() {
	password, err := atoll.NewPassword(16, []atoll.Level{atoll.Digit, atoll.Lowercase})
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	fmt.Println(passphrase)
	// Example output:
	// eremite&align&coward&casing&atoll&maximum&user&adult
}

func ExampleNewPassphrase() {
	passphrase, err := atoll.NewPassphrase(5, atoll.NoList)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(passphrase)
	// Example output:
	// ynuafnezm hvoq asruso jvoe psiro
}
