package atoll

import (
	"fmt"
	"log"
)

func ExampleNewPassword() {
	password, err := NewPassword(16, []int{1, 2, 3, 4, 5}, "", "", true)
	if err != nil {
		log.Fatalf("Failed creating password: %v", err)
	}

	fmt.Println(password)
	// Example output:
	// ?{{5Rt%r3OrE}7?z
}

func ExampleNewPassphrase() {
	passphrase, err := NewPassphrase(5, "/", nil, nil, NoList)
	if err != nil {
		log.Fatalf("Failed creating passphrase: %v", err)
	}

	fmt.Println(passphrase)
	// Example output:
	// bdxiuivb/askyuionzaa/qojbkjizproh/oldir/heox
}

func ExamplePassword_Generate() {
	p := &Password{
		Length:  22,
		Format:  []int{1, 2, 3},
		Include: "1+=",
		Exclude: "&r/e",
		Repeat:  false,
	}

	if err := p.Generate(); err != nil {
		log.Fatalf("Couldn't generate the password: %v", err)
	}

	fmt.Println(p.Entropy)
	// Output: 129.4181470859605
}

func ExamplePassphrase_Generate() {
	p := &Passphrase{
		Length:    8,
		Separator: "&",
		Include:   []string{"atoll"},
		Exclude:   []string{"watermelon"},
	}

	if err := p.Generate(WordList); err != nil {
		log.Fatalf("Couldn't generate the password: %v", err)
	}

	fmt.Println(p.Secret)
	fmt.Println(p.Entropy)
	// Example output:
	// eremite&align&coward&casing&atoll&maximum&user&adult
	// 962.9837392977805
}
