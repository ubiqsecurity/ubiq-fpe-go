package ubiq

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
)

type FF1 struct {
	ctx *ffx
}

func NewFF1(key []byte, twk []byte,
	mintwk int, maxtwk int,
	radix int) (*FF1, error) {
	var err error

	this := new(FF1)
	this.ctx, err = newFFX(key, twk, 1<<32, mintwk, maxtwk, radix)

	return this, err
}

func bigIntPow(b *big.Int, e int) *big.Int {
	r := big.NewInt(0)

	if e > 0 {
		r.Set(b)
		e--

		for ; e > 0; e-- {
			r.Mul(r, b)
		}
	}

	return r
}

func (this *FF1) cipher(X string, T []byte, enc bool) (string, error) {
	var A, B, Y string
	var c, y *big.Int

	c = big.NewInt(0)
	y = big.NewInt(0)

	n := len(X)
	u := n / 2
	v := n - u

	b := int(math.Ceil(math.Log2(
		float64(this.ctx.radix))*float64(v))+7) / 8
	d := 4*((b+3)/4) + 4

	P := make([]byte, 16)
	R := make([]byte, ((d+15)/16)*16)

	if T == nil {
		T = this.ctx.twk
	}

	if n < this.ctx.len.txt.min ||
		n > this.ctx.len.txt.max ||
		len(T) < this.ctx.len.twk.min ||
		(this.ctx.len.twk.max > 0 &&
			len(T) > this.ctx.len.twk.max) {
		return "", errors.New("invalid text and/or tweak length")
	}

	Q := make([]byte, ((len(T)+b+1+15)/16)*16)

	if enc {
		A = X[:u]
		B = X[u:]
	} else {
		B = X[:u]
		A = X[u:]
	}

	P[0] = 1
	P[1] = 2
	binary.BigEndian.PutUint32(P[2:6], uint32(this.ctx.radix))
	P[2] = 1
	P[6] = 10
	P[7] = byte(u)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(len(T)))

	copy(Q[0:], T[:])
	memset(Q[len(T):len(Q)-(b+1)], 0)

	for i := 0; i < 10; i++ {
		var m int

		if (enc && i%2 == 0) ||
			(!enc && i%2 == 1) {
			m = u
		} else {
			m = v
		}

		if enc {
			Q[len(Q)-b-1] = byte(i)
		} else {
			Q[len(Q)-b-1] = byte(9 - i)
		}

		c.SetString(B, this.ctx.radix)
		nb := c.Bytes()
		if b <= len(nb) {
			copy(Q[len(Q)-b:], nb[:])
		} else {
			memset(Q[len(Q)-b:len(Q)-len(nb)], 0)
			copy(Q[len(Q)-len(nb):], nb[:])
		}

		this.ctx.prf(R[0:16], append(P, Q...))

		for j := 1; j < len(R)/16; j++ {
			l := j * 16

			memset(R[l:l+12], 0)
			binary.BigEndian.PutUint32(R[l+12:l+16], uint32(j))

			memxor(R[l:l+16], R[0:16], R[l:l+16])

			this.ctx.ciph(R[l:l+16], R[l:l+16])
		}

		y.SetBytes(R[:d])

		c.SetString(A, this.ctx.radix)
		if enc {
			c.Add(c, y)
		} else {
			c.Sub(c, y)
		}

		y.SetInt64(int64(this.ctx.radix))
		y = bigIntPow(y, m)

		c.Mod(c, y)

		A = B
		B = this.ctx.str(c, m)
	}

	if enc {
		Y = A + B
	} else {
		Y = B + A
	}

	return Y, nil
}

func (this *FF1) Encrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, true)
}

func (this *FF1) Decrypt(X string, T []byte) (string, error) {
	return this.cipher(X, T, false)
}
