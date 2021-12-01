package ubiq

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"math/big"
	"strings"
)

type ffx struct {
	block cipher.Block

	radix int
	len   struct {
		txt, twk struct {
			min, max int
		}
	}
	twk []byte
}

func newFFX(key, twk []byte, maxtxt, mintwk, maxtwk, radix int) (*ffx, error) {
	if radix < 2 || radix > 36 {
		return nil, errors.New("unsupported radix")
	}

	mintxt := int(math.Ceil(float64(6) / math.Log10(float64(radix))))
	if mintxt < 2 || mintxt > maxtxt {
		return nil, errors.New(
			"unsupported radix/maximum text length combination")
	}

	if twk == nil {
		twk = make([]byte, 0)
	}

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

	this.twk = twk

	return this, nil
}

func (this *ffx) prf(d, s []byte) error {
	blockSize := this.block.BlockSize()
	mode := cipher.NewCBCEncrypter(
		this.block,
		[]byte{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		})

	for i := 0; i < len(s); i += blockSize {
		mode.CryptBlocks(d, s[i:i+blockSize])
	}

	return nil
}

func (this *ffx) ciph(d, s []byte) error {
	return this.prf(d, s)
}

func (this *ffx) str(i *big.Int, c int) string {
	s := i.Text(this.radix)
	return strings.Repeat("0", c-len(s)) + s
}

func memset(s []byte, c int) {
	for i := 0; i < len(s); i++ {
		s[i] = byte(c)
	}
}

func memxor(d, s1, s2 []byte) {
	l := len(s1)
	if len(s2) < l {
		l = len(s2)
	}
	if len(d) < l {
		l = len(d)
	}

	for i := 0; i < l; i++ {
		d[i] = s1[i] ^ s2[i]
	}
}
