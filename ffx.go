package ubiq

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"math/big"
	"strings"
)

// common structure used by fpe algorithms
type ffx struct {
	// aes 128, 192, or 256. depends on key size
	// mode (cbc) is not specified here. that's done
	// when the encryption is actually performed
	block cipher.Block

	radix int
	// minimum and maximum lengths allowed for
	// {plain,cipher}text and tweaks
	len struct {
		txt, twk struct {
			min, max int
		}
	}
	// the default tweak; this is never nil. in
	// the event that nil is specified, this will
	// be an empty (0-byte) slice
	twk []byte
}

// allocate a new FFX context
// @twk may be nil
// @mintxt is not supplied as it is determined by the radix
func newFFX(key, twk []byte, maxtxt, mintwk, maxtwk, radix int) (*ffx, error) {
	if radix < 2 || radix > 36 {
		return nil, errors.New("unsupported radix")
	}

	// for both ff1 and ff3-1: radix**minlen >= 1000000
	//
	// therefore:
	//   minlen = ceil(log_radix(1000000))
	//          = ceil(log_10(1000000) / log_10(radix))
	//          = ceil(6 / log_10(radix))
	mintxt := int(math.Ceil(float64(6) / math.Log10(float64(radix))))
	if mintxt < 2 || mintxt > maxtxt {
		return nil, errors.New(
			"unsupported radix/maximum text length combination")
	}

	// default tweak is always non-nil
	if twk == nil {
		twk = make([]byte, 0)
	}

	// make sure tweak length and limits are all compatible
	if mintwk > maxtwk || len(twk) < mintwk ||
		(maxtwk > 0 && len(twk) > maxtwk) {
		return nil, errors.New("invalid tweak length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	this := new(ffx)

	this.block = block

	this.radix = radix

	this.len.txt.min = mintxt
	this.len.txt.max = maxtxt

	this.len.twk.min = mintwk
	this.len.twk.max = maxtwk

	this.twk = make([]byte, len(twk))
	copy(this.twk[:], twk[:])

	return this, nil
}

// perform an aes-cbc of the input @s (which must be a multiple
// of 16 bytes long), returning only the last block of cipher
// text in @d. @d and @s may be the same slice but may not
// otherwise overlap
func (this *ffx) prf(d, s []byte) error {
	blockSize := this.block.BlockSize()
	mode := cipher.NewCBCEncrypter(
		// IV is always 0's
		this.block, bytes.Repeat([]byte{0}, blockSize))

	for i := 0; i < len(s); i += blockSize {
		mode.CryptBlocks(d, s[i:i+blockSize])
	}

	return nil
}

// perform an aes-ecb encryption of @s, placing the result
// in @d. @d and @s may overlap in any way
func (this *ffx) ciph(d, s []byte) error {
	// prf does cbc, but we're only going to encrypt
	// a single block which is functionally equivalent
	// to ecb
	return this.prf(d, s[0:16])
}

// convert a big integer to a string in the specified radix,
// padding the output to the left with 0's
func (this *ffx) str(i *big.Int, c int) string {
	s := i.Text(this.radix)
	return strings.Repeat("0", c-len(s)) + s
}

// reverse the bytes in a slice. @d and @s may be the
// same slice but may not otherwise overlap
func revb(d, s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = s[j], s[i]
	}
}

// reverse a string
func revs(s string) string {
	r := []rune(s)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
