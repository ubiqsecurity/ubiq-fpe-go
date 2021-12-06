package ubiq

import (
	"errors"
	"math"
	"math/big"
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
// @radix species the radix of the input/output data
func NewFF3_1(key, twk []byte, radix int) (*FF3_1, error) {
	var err error

	// ff3-1 uses the reversed value of the  given key
	K := make([]byte, len(key))
	revb(K[:], key[:])

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
		radix)

	return this, err
}

// encryption and decryption are largely the same and are implemented
// in this single function with differences handled depending on the
// value of the @enc parameter. @X is the input, @T is the tweak,
// and the result is returned
//
// The comments below reference the steps of the algorithm described here:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
func (this *FF3_1) cipher(X string, T []byte, enc bool) (string, error) {
	var A, B, Y string
	var c, m, y *big.Int

	// Step 1
	n := len(X)
	v := n / 2
	u := n - v

	// use the default tweak if none is specified
	if T == nil {
		T = this.ctx.twk
	}

	if n < this.ctx.len.txt.min ||
		n > this.ctx.len.txt.max {
		return "", errors.New("invalid text length")
	} else if len(T) < this.ctx.len.twk.min ||
		(this.ctx.len.twk.max > 0 &&
			len(T) > this.ctx.len.twk.max) {
		return "", errors.New("invalid tweak length")
	}

	c = big.NewInt(0)
	m = big.NewInt(0)
	y = big.NewInt(0)

	P := make([]byte, 16)
	Tw := make([][]byte, 2)

	// Step 2
	if enc {
		A = X[:u]
		B = X[u:]
	} else {
		B = X[:u]
		A = X[u:]
	}

	// Step 3
	Tw[0] = make([]byte, 4)
	copy(Tw[0][0:3], T[0:3])
	Tw[0][3] = T[3] & 0xf0

	Tw[1] = make([]byte, 4)
	copy(Tw[1][0:3], T[4:7])
	Tw[1][3] = (T[3] & 0x0f) << 4

	for i := 0; i < 8; i++ {
		// Step 4i
		W := Tw[0]
		m.SetUint64(uint64(v))

		if (enc && i%2 == 0) ||
			(!enc && i%2 == 1) {
			W = Tw[1]
			m.SetUint64(uint64(u))
		}

		// Step 4ii
		copy(P[:4], W[:4])
		if enc {
			P[3] ^= byte(i)
		} else {
			P[3] ^= byte(7 - i)
		}

		// reverse B and export the numeral string
		// to the underlying byte representation of
		// the integer
		c.SetString(revs(B), this.ctx.radix)
		nb := c.Bytes()
		if 12 <= len(nb) {
			copy(P[4:], nb[:12])
		} else {
			// pad on the left with 0's, if needed
			memset(P[4:len(P)-len(nb)], 0)
			copy(P[len(P)-len(nb):], nb[:])
		}

		// Step 4iii
		revb(P[:], P[:])
		this.ctx.ciph(P[:], P[:])
		revb(P[:], P[:])

		// Step 4iv
		y.SetBytes(P[:])

		// Step 4v
		// c = A +/- P
		c.SetString(revs(A), this.ctx.radix)
		if enc {
			c.Add(c, y)
		} else {
			c.Sub(c, y)
		}

		// set y to radix**m
		y.SetUint64(uint64(this.ctx.radix))
		y.Exp(y, m, nil)

		// c = A +/- P mod radix**m
		c.Mod(c, y)

		// Step 4vii
		A = B
		// Step 4vi, 4viii
		B = revs(this.ctx.str(c, int(m.Int64())))
	}

	// Step 5
	if enc {
		Y = A + B
	} else {
		Y = B + A
	}

	return Y, nil
}

// Encrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF3_1) Encrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, true)
}

// Decrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF3_1) Decrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, false)
}
