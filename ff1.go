package ubiq

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
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
// @radix species the radix of the input/output data
func NewFF1(key, twk []byte, mintwk, maxtwk, radix int) (*FF1, error) {
	var err error

	// the maximum allowed input size for FF1 is defined by
	// the algorithm and hard coded as 2**32
	this := new(FF1)
	this.ctx, err = newFFX(key, twk, 1<<32, mintwk, maxtwk, radix)

	return this, err
}

// encryption and decryption are largely the same and are implemented
// in this single function with differences handled depending on the
// value of the @enc parameter. @X is the input, @T is the tweak,
// and the result is returned
//
// The comments below reference the steps of the algorithm described here:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
func (this *FF1) cipher(X string, T []byte, enc bool) (string, error) {
	var A, B, Y string
	var c, m, y *big.Int

	c = big.NewInt(0)
	m = big.NewInt(0)
	y = big.NewInt(0)

	// Step 1
	n := len(X)
	u := n / 2
	v := n - u

	// Step 3, 4
	b := int(math.Ceil(math.Log2(
		float64(this.ctx.radix))*float64(v))+7) / 8
	d := 4*((b+3)/4) + 4

	// use default tweak if none is specified
	if T == nil {
		T = this.ctx.twk
	}

	// P and Q are independently filled-in/populated, but
	// Q is appended to P for the purposes of en/decrypting
	// data. Therefore P is made large enough to accommodate
	// both and Q is a slice of P, thereby avoiding having
	// to repeatedly concatenate them on the fly
	P := make([]byte, 16+((len(T)+b+1+15)/16)*16)
	Q := P[16:]
	R := make([]byte, ((d+15)/16)*16)

	if n < this.ctx.len.txt.min ||
		n > this.ctx.len.txt.max {
		return "", errors.New("invalid text length")
	} else if len(T) < this.ctx.len.twk.min ||
		(this.ctx.len.twk.max > 0 &&
			len(T) > this.ctx.len.twk.max) {
		return "", errors.New("invalid tweak length")
	}

	// Step 2
	if enc {
		A = X[:u]
		B = X[u:]
	} else {
		B = X[:u]
		A = X[u:]
	}

	// Step 3
	P[0] = 1
	P[1] = 2
	// note that this overwrites index 2, but we aren't interested
	// in the 8 bits that are placed there (the upper 8 bits of the
	// radix), so that byte is subsequently overwritten with the
	// hard-coded value of two (specified by the algorithm)
	binary.BigEndian.PutUint32(P[2:6], uint32(this.ctx.radix))
	P[2] = 1
	P[6] = 10
	P[7] = byte(u)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(len(T)))

	// Step 6i, partial
	// these parts of Q are static
	copy(Q[0:], T[:])
	memset(Q[len(T):len(Q)-(b+1)], 0)

	for i := 0; i < 10; i++ {
		// Step 6v
		// m is a big integer for compatibility
		// with go's big integer interfaces later
		if (enc && i%2 == 0) ||
			(!enc && i%2 == 1) {
			m.SetUint64(uint64(u))
		} else {
			m.SetUint64(uint64(v))
		}

		// Step 6i, partial
		if enc {
			Q[len(Q)-b-1] = byte(i)
		} else {
			Q[len(Q)-b-1] = byte(9 - i)
		}

		// convert the numeral string @B to its
		// underlying representation as a string
		// of bytes and store it in Q
		c.SetString(B, this.ctx.radix)
		nb := c.Bytes()
		if b <= len(nb) {
			copy(Q[len(Q)-b:], nb[:])
		} else {
			// pad to the left with 0's, if needed
			memset(Q[len(Q)-b:len(Q)-len(nb)], 0)
			copy(Q[len(Q)-len(nb):], nb[:])
		}

		// Step 6ii
		this.ctx.prf(R[0:16], P)

		// Step 6iii
		// if R is longer than 16 bytes, fill the 2nd and
		// subsequent 16 byte blocks with the result of
		// ciph(R[0:16] ^ 1), ciph(R[0:16] ^2), ...
		for j := 1; j < len(R)/16; j++ {
			l := j * 16

			memset(R[l:l+12], 0)
			binary.BigEndian.PutUint32(R[l+12:l+16], uint32(j))

			memxor(R[l:l+16], R[0:16], R[l:l+16])

			this.ctx.ciph(R[l:l+16], R[l:l+16])
		}

		// Step 6iv
		// create an integer from the first d bytes of R
		y.SetBytes(R[:d])

		// Step 6vi
		// c = A +/- R
		c.SetString(A, this.ctx.radix)
		if enc {
			c.Add(c, y)
		} else {
			c.Sub(c, y)
		}

		// y = radix ** m
		y.SetUint64(uint64(this.ctx.radix))
		y.Exp(y, m, nil)

		// c = (A +/- R) mod radix**m
		c.Mod(c, y)

		// Step 6viii
		A = B
		// Step 6vii, 6ix
		B = this.ctx.str(c, int(m.Int64()))
	}

	// Step 7
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
func (this *FF1) Encrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, true)
}

// Decrypt a string @X with the tweak @T
//
// @T may be nil, in which case the default tweak will be used
func (this *FF1) Decrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, false)
}
