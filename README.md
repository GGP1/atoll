# Atoll

[![PkgGoDev](https://pkg.go.dev/badge/github.com/GGP1/atoll)](https://pkg.go.dev/github.com/GGP1/atoll)
[![Go Report Card](https://goreportcard.com/badge/github.com/GGP1/atoll)](https://goreportcard.com/report/github.com/GGP1/atoll)

Atoll is a library for generating cryptographically secure and highly random secrets.

## Features

- High level of randomness
- Well tested
- No dependencies
- Input validation
- Secret sanitization
- Include characters/words/syllables in random positions
- Exclude any undesired character/word/syllable
- **Password**:
    * 5 different [levels](#password-levels) (custom levels can be used as well)
    * Enable/disable character repetition
- **Passphrase**:
    * Choose between Word, Syllable or No list options to generate the passphrase
    * Custom word/syllable separator

## Installation

```
go get -u github.com/GGP1/atoll
```

## Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/GGP1/atoll"
)

func main() {
    p := &atoll.Password{
        Length: 16,
        Levels: []int{atoll.Lower, atoll.Upper, atoll.Digit},
        Include: "a&1",
        Repeat: true,
    }
    password, err := atoll.NewSecret(p)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(password)
    // 1VOKM7mNA6w&oIan

    p1 := &atoll.Passphrase{
        Length: 7,
        Separator: "/",
        List: atoll.NoList,
    }
    passphrase, err := atoll.NewSecret(p1)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(passphrase)
    // aei/jwyjidaasres/duii/rscfiotuuckm/ydsiacf/ora/yywu
}
```

Head over [example_test.go](/example_test.go) to see more examples.

## Documentation

### Password levels

Atoll guarantees that the password will contain at least one of the characters of each level selected (except Space¹), only if the length of the password is higher than the number of levels.

¹ If the level *Space* is used or the user includes a *space* it isn't 100% sure that the space will be part of the secret, as it could be at the end or the start of the password and it would be deleted and replaced by the sanitizer.

1. Lowecases (a, b, c...)
2. Uppercases (A, B, C...)
3. Digits (1, 2, 3...)
4. Space
5. Special (!, $, %...)

### Passphrases options

Atoll offers 3 ways of generating a passphrase:

- **Without** a list (*NoList*): generates random numbers that determine the word length (between 3 and 12 letters) and if the letter is either a vowel or a constant. Note that not using a list makes the potential attacker job harder.

- With a **Word** list (*WordList*): random words are taken from a 18,235 long word list.
    
- With a **Syllable** list (*SyllableList*): random syllables are taken from a 10,129 long syllable list.

### Randomness

> Randomness is a measure of the observer's ignorance, not an inherent quality of a process.

Atoll uses the "crypto/rand" package to generate **cryptographically secure** random numbers, which "select" the characters-words-syllables from different pools as well as the indices when generating a password.

### Entropy

Entropy is a **measure of the uncertainty of a system**. The concept is a difficult one to grasp fully and is confusing, even to experts. Strictly speaking, any given passphrase has an entropy of zero because it is already chosen. It is the method you use to randomly select your passphrase that has entropy. Entropy tells how hard it will be to guess the passphrase itself even if an attacker knows the method you used to select your passphrase. A passphrase is more secure if it is selected using a method that has more entropy. Entropy is measured in bits. The outcome of a single coin toss -- "heads or tails" -- has one bit of entropy. - *Arnold G. Reinhold*.

> Entropy = log2(poolLength ^ secretLength)

The French National Cybersecurity Agency (ANSSI) recommends secrets having a minimum of 100 bits when it comes to passwords or secret keys for encryption systems that absolutely must be secure. In fact, the agency recommends 128 bits to guarantee security for several years. It considers 64 bits to be very small (very weak); 64 to 80 bits to be small; and 80 to 100 bits to be medium (moderately strong).

### Keyspace

Keyspace is the set of all possible permutations of a key. On average, half the key space must be searched to find the solution.

> Keyspace = poolLength ^ secretLength

### Seconds to crack

> When calculating the seconds to crack the secret what is considered is a brute force attack. Dictionary and social engineering attacks (like shoulder surfing. pretexting, etc) are left out of consideration.

The time taken in seconds by a brute force attack to crack a secret is calculated by doing `keyspace / guessesPerSecond` where the guesses per second is 1 trillon, this is the number Edward Snowden said we should be prepared for and might be changed in the future.

In 2019 a record was set for a computer trying to generate every conceivable password. It achieved a rate faster than 100 billion guesses per second.

## Benchmarks

```
BenchmarkPassword-6                  	   81109	     14708 ns/op	    3734 B/op	     143 allocs/op
BenchmarkNewPassword-6               	   82390	     14502 ns/op	    3329 B/op	     150 allocs/op
BenchmarkNewPassphrase-6             	   38400	     31080 ns/op	    5671 B/op	     392 allocs/op
BenchmarkPassphrase_NoList-6         	   43736	     27586 ns/op	    4991 B/op	     350 allocs/op
BenchmarkPassphrase_WordList-6       	  335258	      3634 ns/op	     752 B/op	      45 allocs/op
BenchmarkPassphrase_SyllableList-6   	  352632	      3537 ns/op	     736 B/op	      45 allocs/op
```

Take a look at them [here](/benchmark_test.go).

## License

Atoll is licensed under the [MIT](/LICENSE) license.