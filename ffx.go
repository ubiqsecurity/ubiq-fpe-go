package ubiq

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
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

func newFFX(key []byte, twk []byte,
	maxtxt int, maxtwk int, mintwk int,
	radix int) (*ffx, error) {

	if radix < 2 || radix > 36 {
		return nil, errors.New("unsupported radix")
	}

	mintxt := int(math.Ceil(float64(6) / math.Log10(float64(radix))))
	if mintxt < 2 || mintxt > maxtxt {
		return nil, errors.New(
			"unsupported radix/maximum text length combination")
	}

	if mintwk > maxtwk || len(twk) < mintwk ||
		(maxtwk > 0 && len(twk) > maxtwk) {
		return nil, errors.New("invalid tweak length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ctx := new(ffx)

	ctx.block = block

	ctx.radix = radix

	ctx.len.txt.min = mintxt
	ctx.len.txt.max = maxtxt

	ctx.len.twk.min = mintwk
	ctx.len.twk.max = maxtwk

	ctx.twk = twk

	return ctx, nil
}
