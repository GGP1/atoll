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
	// ?{{5Rt%r3OrE}7?z
}

func ExampleNewPassphrase() {
	passphrase, err := NewPassphrase(8, "/", nil, nil, NoList)
	if err != nil {
		log.Fatalf("Failed creating passphrase: %v", err)
	}

	fmt.Println(passphrase)
	// bku/wxnpeg/gaagvqocrns/pautyo/ciklw/fkqq/ovaoqv/zxoabgeo
}

func ExamplePassword() {
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

func ExamplePassphrase() {
	p := &Passphrase{
		Length:    10,
		Separator: "&",
		Include:   []string{"atoll"},
		Exclude:   []string{"watermelon"},
	}

	if err := p.Generate(WordList); err != nil {
		log.Fatalf("Couldn't generate the password: %v", err)
	}

	fmt.Println(p.Entropy)
	// 962.9837392977805
}
