# Atoll

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://godoc.org/github.com/GGP1/atoll)
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
$ go get github.com/GGP1/atoll
```

## Features

- Secret sanitization 
    * Common patterns cleanup, code points normalization -NFKC- and space trimming
- Include characters/words/syllables in random positions
- Exclude any characters/words/syllables
- Secret entropy in bits

- **Password**:
    * Up to 5 different [format levels](#password-format-levels)
    * Enable/disable character repetition

- **Passphrase**:
    * Choose between Word, Syllable or No list options
    * Custom word/syllable separator

## Examples

Head over [example_test.go](/example_test.go) to see some examples.

## Documentation

### Password format levels

> 2 byte code points (¡, £, ¿, etc) are not used as they may cause errors

1. Lowecases (a, b, c...)
2. Uppercases (A, B, C...)
3. Digits (1, 2, 3...)
4. Space
5. Special (!, $, %...)

### Passphrases options

Atoll offers 3 ways of generating a passphrase:
    - *Without* a list <NoList>: generate random numbers that determine the word length (between 3 and 12 letters) and if the letter is a vowel or a constant (4/10 times a vowel is selected). Note that not using a list makes the potential attacker job harder.
    - With a *Word* list <WordList>: random words are taken from a 18,235 long word list.
    - With a *Syllable* list <SyllableList>: random syllables are taken from a 10,129 long syllable list.

### Randomness

> Note: randomness is a measure of the observer's ignorance, not an inherent quality of a process.

Having this into account, atoll uses the crypto/rand package to generate **cryptographically secure** random numbers and using them to select characters/words/syllables from different pools.

### Entropy

> Entropy is a measure of the uncertainty or randomness of a system. The concept is a difficult one to grasp fully and is confusing, even to experts. Strictly speaking, any given passphrase has an entropy of zero because it is already chosen. It is the method you use to randomly select your passphrase that has entropy. Entropy tells how hard it will be to guess the passphrase itself even if an attacker knows the method you used to select your passphrase. A passphrase is more secure if it is selected using a method that has more entropy. Entropy is measured in bits. The outcome of a single coin toss -- "heads or tails" -- has one bit of entropy. - Arnold G. Reinhold

Entropy calculation: log2(poolLength ^ secretLength)

### More calculations

In case you want to obtain more information about the secret security, here are some calculations:

> What is calculated is the 50% of a brute force attack (this is the average an attacker will take to crack the password). Dictionary and social engineering attacks (like shoulder surfing. pretexting, etc) are left out of consideration.

- Number of *possible secrets* that the algorithm can generate: entropy ^ 2

- Number of *attempts* to crack the secret: (entropy ^ 2) / 2

- Seconds to crack: 
    > 1,000,000,000,000,000 (1 trilon) is the number of guesses per second Edward Snowden said we should be prepared for
    * Password: (((entropy ^ 2) / 1,000,000,000,000,000) / 2)
    * Passphrase: 
        words := strings.Split(p.Secret, p.Separator)
        NoList: 26^eachWordLen^len(words) -> iterate over words and sum each word length
        WordList and SyllableList: (((entropy ^ 2) - len(words)) / 1,000,000,000,000,000) / 2

## Benchmarks

```
BenchmarkNewPassword                     52402             21698 ns/op      
BenchmarkPassword                        54054             21738 ns/op      
BenchmarkNewPassphrase                   24340             47618 ns/op      
BenchmarkPassphrase_NoList               26902             45387 ns/op      
BenchmarkPassphrase_WordList            279070              3852 ns/op      
BenchmarkPassphrase_SyllableList        315930              3611 ns/op 
```

## License

Atoll is licensed under the [MIT](/LICENSE) license.