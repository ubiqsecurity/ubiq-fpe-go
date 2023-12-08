package ubiq

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

// Context structure for FF1 FPE algorithm
type FF1 struct {
	ctx *ffx
}

// Allocate a new FF1 context structure
//
// @key specifies the key for the algorthim, the length of which will
// determine the underlying aes encryption to use.
//
// @twk specifies the default tweak to be used if one is not specified
// to the Encrypt or Decrypt functions. nil is allowed
//
// @mintwk and @maxtwk specify the minimum and maximum tweak sizes allowed
// by the algorithm. both may be set to 0 to indicate that there is no
// limit on the tweak size
//
// @radix specifies the radix of the input/output data
//
// the function also accepts an optional argument:
// @alpha is a string containing the alphabet for numerical conversions
func NewFF1(key, twk []byte, mintwk, maxtwk, radix int, args ...interface{}) (
	*FF1, error) {
	var err error

	// the maximum allowed input size for FF1 is defined by
	// the algorithm and hard coded as 2**32
	this := new(FF1)
	this.ctx, err = newFFX(key, twk, 1<<32, mintwk, maxtwk, radix, args...)

	return this, err
}

// encryption and decryption are largely the same and are implemented
// in this single function with differences handled depending on the
// value of the @enc parameter. @X is the input, @T is the tweak,
// and the result is returned
//
// The comments below reference the steps of the algorithm described here:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
func (this *FF1) cipher(X []rune, T []byte, enc bool) ([]rune, error) {
	var radix int = this.ctx.alpha.Len()

	ctx := this.ctx

	n := len(X)
	u := n / 2
	v := n - u

	b := int(math.Ceil(math.Log2(
		float64(radix))*float64(v))+7) / 8
	d := 4*((b+3)/4) + 4

	// use default tweak if none is specified
	if T == nil {
		T = ctx.twk
	}

	// P and Q are independently filled-in/populated, but
	// Q is appended to P for the purposes of en/decrypting
	// data. Therefore P is made large enough to accommodate
	// both and Q is a slice of P, thereby avoiding having
	// to repeatedly concatenate them on the fly
	P := make([]byte, 16+((len(T)+b+1+15)/16)*16)
	Q := P[16:]
	R := make([]byte, ((d+15)/16)*16)

	if n < ctx.len.txt.min ||
		n > ctx.len.txt.max {
		return nil, errors.New("invalid text length")
	} else if len(T) < ctx.len.twk.min ||
		(ctx.len.twk.max > 0 &&
			len(T) > ctx.len.twk.max) {
		return nil, errors.New("invalid tweak length")
	}

	P[0] = 1
	P[1] = 2
	// note that this overwrites index 2, but we aren't interested
	// in the 8 bits that are placed there (the upper 8 bits of the
	// radix), so that byte is subsequently overwritten with the
	// hard-coded value of one (specified by the algorithm)
	binary.BigEndian.PutUint32(P[2:6], uint32(radix))
	P[2] = 1
	P[6] = 10
	P[7] = byte(u)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(len(T)))

	// this part of Q is static
	copy(Q, bytes.Repeat([]byte{0}, len(Q)))
	copy(Q, T)

	ctx.y.SetUint64(uint64(radix))
	ctx.mU.SetUint64(uint64(u))
	ctx.mU.Exp(ctx.y, ctx.mU, nil)
	ctx.mV.Set(ctx.mU)
	if u != v {
		ctx.mV.Mul(ctx.mV, ctx.y)
	}

	RunesToBigInt(ctx.nA, &ctx.alpha, X[:u])
	RunesToBigInt(ctx.nB, &ctx.alpha, X[u:])
	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
		ctx.mU, ctx.mV = ctx.mV, ctx.mU
	}

	for i := 0; i < 10; i++ {
		if enc {
			Q[len(Q)-b-1] = byte(i)
		} else {
			Q[len(Q)-b-1] = byte(9 - i)
		}

		ctx.nB.FillBytes(Q[len(Q)-b:])
		ctx.prf(R[0:16], P)

		// if R is longer than 16 bytes, fill the 2nd and
		// subsequent 16 byte blocks with the result of
		// ciph(R[0:16] ^ 1), ciph(R[0:16] ^2), ...
		for j := 1; j < len(R)/16; j++ {
			l := j * 16
			w := binary.BigEndian.Uint32(R[12:16])

			binary.BigEndian.PutUint32(R[12:16], w^uint32(j))
			ctx.ciph(R[l:l+16], R[:16])
			binary.BigEndian.PutUint32(R[12:16], uint32(w))
		}

		// create an integer from the first d bytes of R
		ctx.y.SetBytes(R[:d])

		// c = A +/- R
		if enc {
			ctx.nA.Add(ctx.nA, ctx.y)
		} else {
			ctx.nA.Sub(ctx.nA, ctx.y)
		}

		ctx.nA, ctx.nB = ctx.nB, ctx.nA

		ctx.nB.Mod(ctx.nB, ctx.mU)
		ctx.mU, ctx.mV = ctx.mV, ctx.mU
	}

	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
	}

	return append(
			BigIntToRunes(&ctx.alpha, ctx.nA, u),
			BigIntToRunes(&ctx.alpha, ctx.nB, v)...),
		nil
}

func (this *FF1) EncryptRunes(X []rune, T []byte) ([]rune, error) {
	return this.cipher(X, T, true)
}

// Encrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF1) Encrypt(X string, T []byte) (Y string, err error) {
	Yr, err := this.EncryptRunes([]rune(X), T)
	if err == nil {
		Y = string(Yr)
	}
	return Y, err
}

func (this *FF1) DecryptRunes(X []rune, T []byte) ([]rune, error) {
	return this.cipher(X, T, false)
}

// Decrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF1) Decrypt(X string, T []byte) (Y string, err error) {
	Yr, err := this.DecryptRunes([]rune(X), T)
	if err == nil {
		Y = string(Yr)
	}
	return Y, err
}
