# Atoll

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://godoc.org/github.com/GGP1/atoll)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/GGP1/atoll)](https://pkg.go.dev/github.com/GGP1/atoll)
[![Go Report Card](https://goreportcard.com/badge/github.com/GGP1/atoll)](https://goreportcard.com/report/github.com/GGP1/atoll)

Atoll is a package for generating secure random secrets.

# Table of contents

- [Installation](#installation)
- [Features](#features)
- [Examples](#examples)
- [Documentation](#documentation)
    * [Password format levels](#password-format-levels)
    * [Passphrases options](#passphrases-options)
    * [Randomness](#randomness)
    * [Entropy](#entropy)
    * [More calculations](#more-calculations)   
- [Benchmarks](#benchmarks)
- [License](#license)

## Installation

```
go get -u github.com/GGP1/atoll
```

## Features

- High level of randomness
- Well tested, coverage: 100% of statements
- No dependencies
- Input validation
- Secret sanitization
    * Common patterns cleanup and space trimming
- Include characters/words/syllables in random positions
- Exclude any undesired character/word/syllable
- **Password**:
    * Up to 6 different [format levels](#password-format-levels)
    * Enable/disable character repetition
- **Passphrase**:
    * Choose between Word, Syllable or No list options to generate the passphrase
    * Custom word/syllable separator

## Examples

Head over [example_test.go](/example_test.go) to see more examples.

```
package main

import (
    "fmt"
    "log"

    "github.com/GGP1/atoll"
)

func main() {
    p := &atoll.Password{
        Length: 16,
        Format: []int{1, 2, 3, 4, 5, 6},
        Include: "á&1",
        Repeat: true,
    }

    // This could be done by calling p.Generate() aswell 
    password, err := atoll.NewSecret(p)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(password)

    // A simpler way
    password2, err := atoll.NewPassword(20, []int{1, 2, 3, 4})
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(password2)
}
```

## Documentation

### Password format levels

1. Lowecases (a, b, c...)
2. Uppercases (A, B, C...)
3. Digits (1, 2, 3...)
4. Space
5. Special (!, $, %...)
6. Extended UTF-8 (¡, ¢, £, ¤, ¥...)

### Passphrases options

Atoll offers 3 ways of generating a passphrase:

- **Without** a list (*NoList*): generate random numbers that determine the word length (between 3 and 12 letters) and if the letter is a vowel or a constant (4/10 times a vowel is selected). Note that not using a list makes the potential attacker job harder.

- With a **Word** list (*WordList*): random words are taken from a 18,235 long word list.
    
- With a **Syllable** list (*SyllableList*): random syllables are taken from a 10,129 long syllable list.

### Randomness

> Randomness is a measure of the observer's ignorance, not an inherent quality of a process.

Atoll uses the "crypto/rand" package to generate **cryptographically secure** random numbers and using them to select characters/words/syllables from different pools.

### Entropy

> Entropy is a measure of the uncertainty or randomness of a system. The concept is a difficult one to grasp fully and is confusing, even to experts. Strictly speaking, any given passphrase has an entropy of zero because it is already chosen. It is the method you use to randomly select your passphrase that has entropy. Entropy tells how hard it will be to guess the passphrase itself even if an attacker knows the method you used to select your passphrase. A passphrase is more secure if it is selected using a method that has more entropy. Entropy is measured in bits. The outcome of a single coin toss -- "heads or tails" -- has one bit of entropy. - Arnold G. Reinhold

entropy := log2(poolLength ^ secretLength)

Pool lengths:

1. Password formats:
    * Level 1 (lowercases): 26
    * Level 2 (uppercases): 26
    * Level 3 (digits): 10
    * Level 4 (space): 1
    * Level 5 (specials): 32
    * Level 6 (extendedUTF8): 95
2. Passphrase No list (must be calculated word by word): 26 ^ number of letters in the word
3. Passphrase Word list: 18,325
4. Passphrase Syllable list: 10,129

### More calculations

In case you want to obtain more information about the secret security, here are some calculations:

> What is calculated is the 50% of a brute force attack (this is the average an attacker will take to crack the password). Dictionary and social engineering attacks (like shoulder surfing. pretexting, etc) are left out of consideration.

- Number of *possible secrets* that the algorithm can generate: 2 ^ entropy

- Number of *attempts* to crack the secret: (2 ^ entropy) / 2

- Seconds to crack: 
    > 1,000,000,000,000,000 (1 trillion) is the number of guesses per second Edward Snowden said we should be prepared for
    * Password: (((2 ^ entropy) / 1,000,000,000,000,000) / 2)
    * Passphrase: 

        ```words := strings.Split(p.Secret, p.Separator)```

        NoList: 26^SumWordsLength^len(words) -> iterate over words and sum each word length

        WordList and SyllableList: (((2 ^ entropy) - len(words)) / 1,000,000,000,000,000) / 2

## Benchmarks

GOOS: windows

GOARCH: amd64

GOMAXPROCS: 6

```
BenchmarkPassword                  	   44286	     27166 ns/op	   18725 B/op	     157 allocs/op
BenchmarkNewPassword               	   50005	     23908 ns/op	   16091 B/op	     124 allocs/op
BenchmarkNewPassphrase             	   33240	     36071 ns/op	    7825 B/op	     405 allocs/op
BenchmarkPassphrase_NoList         	   32966	     36492 ns/op	    7832 B/op	     406 allocs/op
BenchmarkPassphrase_WordList       	  374997	      3229 ns/op	     576 B/op	      27 allocs/op
BenchmarkPassphrase_SyllableList   	  400014	      2925 ns/op	     560 B/op	      27 allocs/op
```

Take a look at them [here](/benchmark_test.go).

## License

Atoll is licensed under the [MIT](/LICENSE) license.