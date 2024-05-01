package ubiq

import (
	"errors"
	"math"
)

// Context structure for the FF3-1 FPE algorithm
type FF3_1 struct {
	ctx *ffx
}

// Allocate a new FF3-1 context structure
//
// @key specifies the key for the algorthim, the length of which will
// determine the underlying aes encryption to use.
//
// @twk specifies the default tweak to be used. the tweak must be
// exactly 7 bytes long
//
// @radix specifies the radix of the input/output data
//
// the function also accepts an optional argument:
// @alpha is a string containing the alphabet for numerical conversions
func NewFF3_1(key, twk []byte, radix int, args ...interface{}) (*FF3_1, error) {
	var err error

	// ff3-1 uses the reversed value of the  given key
	K := make([]byte, len(key))
	revb(K, key)

	this := new(FF3_1)
	this.ctx, err = newFFX(K, twk,
		// maxlen for ff3-1:
		// = 2 * log_radix(2**96)
		// = 2 * log_radix(2**48 * 2**48)
		// = 2 * (log_radix(2**48) + log_radix(2**48))
		// = 2 * (2 * log_radix(2**48))
		// = 4 * log_radix(2**48)
		// = 4 * log2(2**48) / log2(radix)
		// = 4 * 48 / log2(radix)
		// = 192 / log2(radix)
		int(float64(192)/math.Log2(float64(radix))),
		7, 7,
		radix, args...)

	return this, err
}

// encryption and decryption are largely the same and are implemented
// in this single function with differences handled depending on the
// value of the @enc parameter. @X is the input, @T is the tweak,
// and the result is returned
//
// The comments below reference the steps of the algorithm described here:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
func (this *FF3_1) cipher(X []rune, T []byte, enc bool) ([]rune, error) {
	ctx := this.ctx

	n := len(X)
	v := n / 2
	u := n - v

	// use the default tweak if none is specified
	if T == nil {
		T = ctx.twk
	}

	if n < ctx.len.txt.min ||
		n > ctx.len.txt.max {
		return nil, errors.New("invalid text length")
	} else if len(T) < ctx.len.twk.min ||
		(ctx.len.twk.max > 0 &&
			len(T) > ctx.len.twk.max) {
		return nil, errors.New("invalid tweak length")
	}

	P := [16]byte{}

	Tw := [2][4]byte{}
	copy(Tw[0][0:3], T[0:3])
	Tw[0][3] = T[3] & 0xf0
	copy(Tw[1][0:3], T[4:7])
	Tw[1][3] = (T[3] & 0x0f) << 4

	ctx.y.SetUint64(uint64(ctx.alpha.Len()))
	ctx.mV.SetUint64(uint64(v))
	ctx.mV.Exp(ctx.y, ctx.mV, nil)
	ctx.mU.Set(ctx.mV)
	if v != u {
		ctx.mU.Mul(ctx.mU, ctx.y)
	}

	A := revr(X[:u])
	RunesToBigInt(ctx.nA, &ctx.alpha, A)
	B := revr(X[u:])
	RunesToBigInt(ctx.nB, &ctx.alpha, B)
	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
		ctx.mU, ctx.mV = ctx.mV, ctx.mU

		Tw[0], Tw[1] = Tw[1], Tw[0]
	}

	for i := 1; i <= 8; i++ {
		copy(P[:4], Tw[i%2][:])

		if enc {
			P[3] ^= byte(i - 1)
		} else {
			P[3] ^= byte(8 - i)
		}

		// export B's numeral string
		// to the underlying byte representation of
		// the integer
		ctx.nB.FillBytes(P[4:16])

		revb(P[:], P[:])
		ctx.ciph(P[:], P[:])
		revb(P[:], P[:])

		// c = A +/- P
		ctx.y.SetBytes(P[:])
		if enc {
			ctx.nA.Add(ctx.nA, ctx.y)
		} else {
			ctx.nA.Sub(ctx.nA, ctx.y)
		}

		ctx.nA, ctx.nB = ctx.nB, ctx.nA

		// c = A +/- P mod radix**m
		ctx.y.Mod(ctx.nB, ctx.mU)
		ctx.y, ctx.nB = ctx.nB, ctx.y

		ctx.mU, ctx.mV = ctx.mV, ctx.mU
	}

	if !enc {
		ctx.nA, ctx.nB = ctx.nB, ctx.nA
	}

	A = BigIntToRunes(&ctx.alpha, ctx.nA, u)
	_revr(A, A)
	B = BigIntToRunes(&ctx.alpha, ctx.nB, v)
	_revr(B, B)

	return append(A, B...), nil
}

func (this *FF3_1) EncryptRunes(X []rune, T []byte) ([]rune, error) {
	return this.cipher(X, T, true)
}

// Encrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF3_1) Encrypt(X string, T []byte) (Y string, err error) {
	Yr, err := this.EncryptRunes([]rune(X), T)
	if err == nil {
		Y = string(Yr)
	}
	return Y, err
}

func (this *FF3_1) DecryptRunes(X []rune, T []byte) ([]rune, error) {
	return this.cipher(X, T, false)
}

// Decrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF3_1) Decrypt(X string, T []byte) (Y string, err error) {
	Yr, err := this.DecryptRunes([]rune(X), T)
	if err == nil {
		Y = string(Yr)
	}
	return Y, err
}
