package ubiq

import (
	"errors"
	"math"
	"math/big"
)

type FF3_1 struct {
	ctx *ffx
}

func NewFF3_1(key, twk []byte, radix int) (*FF3_1, error) {
	var err error

	K := make([]byte, len(key))
	revb(K[:], key[:])

	this := new(FF3_1)
	this.ctx, err = newFFX(K, twk,
		int(float64(192)/math.Log2(float64(radix))),
		7, 7,
		radix)

	return this, err
}

func (this *FF3_1) cipher(X string, T []byte, enc bool) (string, error) {
	var A, B, Y string
	var c, m, y *big.Int

	n := len(X)
	v := n / 2
	u := n - v

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

	if enc {
		A = X[:u]
		B = X[u:]
	} else {
		B = X[:u]
		A = X[u:]
	}

	Tw[0] = make([]byte, 4)
	copy(Tw[0][0:3], T[0:3])
	Tw[0][3] = T[3] & 0xf0

	Tw[1] = make([]byte, 4)
	copy(Tw[1][0:3], T[4:7])
	Tw[1][3] = (T[3] & 0x0f) << 4

	for i := 0; i < 8; i++ {
		var W []byte

		W = Tw[0]
		m.SetUint64(uint64(v))

		if (enc && i%2 == 0) ||
			(!enc && i%2 == 1) {
			W = Tw[1]
			m.SetUint64(uint64(u))
		}

		copy(P[:4], W[:4])
		if enc {
			P[3] ^= byte(i)
		} else {
			P[3] ^= byte(7 - i)
		}

		c.SetString(revs(B), this.ctx.radix)
		nb := c.Bytes()
		if 12 <= len(nb) {
			copy(P[4:], nb[:12])
		} else {
			memset(P[4:len(P)-len(nb)], 0)
			copy(P[len(P)-len(nb):], nb[:])
		}

		revb(P[:], P[:])
		this.ctx.ciph(P[:], P[:])
		revb(P[:], P[:])

		y.SetBytes(P[:])

		c.SetString(revs(A), this.ctx.radix)
		if enc {
			c.Add(c, y)
		} else {
			c.Sub(c, y)
		}

		y.SetUint64(uint64(this.ctx.radix))
		y = y.Exp(y, m, nil)

		c.Mod(c, y)

		A = B
		B = revs(this.ctx.str(c, int(m.Int64())))
	}

	if enc {
		Y = A + B
	} else {
		Y = B + A
	}

	return Y, nil
}

func (this *FF3_1) Encrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, true)
}

func (this *FF3_1) Decrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, false)
}
