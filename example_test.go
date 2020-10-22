package atoll_test

import (
	"fmt"
	"log"

	"github.com/GGP1/atoll"
)

func ExampleNewSecret() {
	password := &atoll.Password{
		Length: 30,
	}

	if err := atoll.NewSecret(password); err != nil {
		log.Fatalf("Failed creating secret: %v", err)
	}

	fmt.Println(password.Secret)
	// Example output:
	// .$'v_kcBg42;U\Ot`fY<%Ps:~aNoKi
}

func ExampleNewPassword() {
	password, err := atoll.NewPassword(16, []int{1, 2, 3, 4, 5})
	if err != nil {
		log.Fatalf("Failed creating password: %v", err)
	}

	fmt.Println(password)
	// Example output:
	// ?{{5Rt%r3OrE}7?z
}

func ExampleNewPassphrase() {
	passphrase, err := atoll.NewPassphrase(5, atoll.NoList)
	if err != nil {
		log.Fatalf("Failed creating passphrase: %v", err)
	}

	fmt.Println(passphrase)
	// Example output:
	// bdxiuivb/askyuionzaa/qojbkjizproh/oldir/heox
}

func ExamplePassword_Generate() {
	p := &atoll.Password{
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
	// Output: 131.50015831699815
}

func ExamplePassphrase_Generate() {
	p := &atoll.Passphrase{
		Length:    8,
		Separator: "&",
		List:      atoll.WordList,
		Include:   []string{"atoll"},
		Exclude:   []string{"watermelon"},
	}

	if err := p.Generate(); err != nil {
		log.Fatalf("Couldn't generate the password: %v", err)
	}

	fmt.Println(p.Secret)
	fmt.Println(p.Entropy)
	// Example output:
	// eremite&align&coward&casing&atoll&maximum&user&adult
	// 962.9837392977805
}
