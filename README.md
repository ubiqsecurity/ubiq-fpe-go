# Format Preserving Encryption in Go

An implementation of the NIST-approved FF1 and FF3-1 algorithms in Go.

This implementation conforms (as best as possible) to
[Draft SP 800-38G Rev. 1][800-38g1]. The implementation passes all tests
specified by NIST in their Cryptographic Standards and Guidelines
[examples for FF1][ff1-examples]; however, no official examples/samples exist
(or are known) for FF3-1. FF3 is not implemented as NIST has officially
deprecated its use in light of recent [cryptanalysis][ff3-cryptanalysis]
performed on it.

# Testing

To run the tests:
```sh
$ go test
```
As described above, the unit tests for FF1 come from the NIST guidelines. As
no such guidelines are available for FF3-1, the unit tests verify only that
the encryption and decryption implementations are compatible with each other.

# Documentation

```sh
$ go doc -all
```

### About alphabets and the radix parameter

The interfaces operate on strings, and the radix parameter determines which
characters are valid within those strings, i.e. the alphabet. For example, if
your radix is 10, then the alphabet for your plain text consists of the
characters in the string "0123456789". If your radix is 16, then the
alphabet is the characters in the string "0123456789abcdef".

More concretely, if you want to encrypt, say, a 16 digit number grouped into
4 groups of 4 using a `-` as a delimiter as in `0123-4567-8901-2345`, then you
would need a radix of at least 11, and you would need to translate the `-`
character to an `a` (as that is the value that follows `9`) prior to the
encryption. Conversely, you would need to translate an `a` to a `-` after
decryption.

This mapping of user inputs to alphabets defined by the radix is not performed
by the library and must be done prior to calling the encrypt and after calling
the decrypt functions.

By default, a radix of up to 36 is supported, and the alphabet for a radix of
36 is "0123456789abcdefghijklmnopqrstuvwxyz". However, he interfaces allow the
caller to specify a custom alphabet that differs from the default. Using a
custom alphabet, radixes up to the number of characters in the alphabet can be
supported. Note that custom alphabets must not contain duplicate characters.

### Tweaks

Tweaks are very much like Initialization Vectors (IVs) in "traditional"
encryption algorithms. For FF1, the minimun and maximum allowed lengths of
the tweak may be specified by the user, and any tweak length between those
values may be used. For FF3-1, the size of the tweak is fixed at 7 bytes.

### Plain/ciphertext input lengths

For both FF1 and FF3-1, the minimum length is determined by the inequality:
- radix<sup>minlen</sup> >= 1000000

or:
- minlen >= 6 / log<sub>10</sub> radix

Thus, the minimum length is determined by the radix and is automatically
calculated from it.

For FF1, the maximum input length is
- 2<sup>32</sup>

For FF3-1, the maximum input length is
- 2 * log<sub>radix</sub> 2<sup>96</sup>

or:
- 192 / log<sub>2</sub> radix

## Examples

The unit test code provides the best and simplest example of how to use the
interfaces.

### FF1
```go
	// K is a slice containing the key
	// T is a slice containing the tweak
	// tweak length is unbounded
	// r is the radix
	ff1, err := NewFF1(K, T, 0, 0, r)
	if err != nil {
		...
	}

	// PT is a slice containing the plaintext
	CT, err := ff1.Encrypt(PT, nil)
	if err != nil {
		...
	}

	PT, err = ff1.Decrypt(CT, nil)
	if err != nil {
		...
	}
```
### FF3-1
```go
	// K is a slice containing the key
	// T is a slice containing the tweak
	// r is the radix
	ff3_1, err := NewFF3_1(K, T, r)
	if err != nil {
		...
	}

	// PT is a slice containing the plaintext
	CT, err := ff3_1.Encrypt(PT, nil)
	if err != nil {
		...
	}

	PT, err = ff3_1.Decrypt(CT, nil)
	if err != nil {
		...
	}
```

[800-38g1]:https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
[ff1-examples]:https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
[ff3-cryptanalysis]:https://csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3
