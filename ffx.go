package ubiq

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"math/big"
)

// common structure used by fpe algorithms
type ffx struct {
	// aes 128, 192, or 256. depends on key size
	// mode (cbc) is not specified here. that's done
	// when the encryption is actually performed
	block cipher.Block

	alpha Alphabet

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

	nA, nB, mU, mV, y *big.Int
}

// allocate a new FFX context
// @twk may be nil
// @mintxt is not supplied as it is determined by the radix
func newFFX(key, twk []byte,
	maxtxt, mintwk, maxtwk, radix int,
	args ...interface{}) (*ffx, error) {
	alpha := defaultAlphabetStr
	if len(args) > 0 {
		alpha = args[0].(string)
	}

	ralph := []rune(alpha)
	if radix < 2 || radix > len(ralph) {
		return nil, errors.New("unsupported radix")
	}
	ralph = ralph[:radix]

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

	this.alpha, _ = NewAlphabet(string(ralph))

	this.len.txt.min = mintxt
	this.len.txt.max = maxtxt

	this.len.twk.min = mintwk
	this.len.twk.max = maxtwk

	this.twk = make([]byte, len(twk))
	copy(this.twk[:], twk[:])

	this.nA = big.NewInt(0)
	this.nB = big.NewInt(0)
	this.mU = big.NewInt(0)
	this.mV = big.NewInt(0)
	this.y = big.NewInt(0)

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
		this.block,
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

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

// convert a big integer to an array of runes in the specified radix,
// padding the output to the left with 0's
func BigIntToRunes(alpha *Alphabet, _n *big.Int, l int) []rune {
	var R []rune
	var i int

	R = make([]rune, l)

	if alpha.Len() <= defaultAlphabet.Len() {
		s := _n.Text(alpha.Len())

		for i = 0; i < len(s); i++ {
			if alpha.IsDef() {
				R[len(s)-i-1] = rune(s[i])
			} else {
				R[len(s)-i-1] = alpha.ValAt(
					defaultAlphabet.PosOf(rune(s[i])))
			}
		}
	} else {
		var n *big.Int = big.NewInt(0)
		var r *big.Int = big.NewInt(0)
		var t *big.Int = big.NewInt(int64(alpha.Len()))

		n.Set(_n)
		for i = 0; !n.IsInt64() || n.Int64() != 0; i++ {
			n.DivMod(n, t, r)
			R[i] = alpha.ValAt(int(r.Int64()))
		}
	}

	for ; i < l; i++ {
		R[i] = alpha.ValAt(0)
	}

	return revr(R)
}

func RunesToBigInt(n *big.Int, alpha *Alphabet, s []rune) *big.Int {
	if alpha.Len() <= defaultAlphabet.Len() {
		b := make([]byte, len(s))

		for i, _ := range s {
			if alpha.IsDef() {
				b[i] = byte(s[i])
			} else {
				b[i] = byte(defaultAlphabet.ValAt(
					alpha.PosOf(s[i])))
			}
		}

		n.SetString(string(b), alpha.Len())
	} else {
		var m *big.Int = big.NewInt(1)
		var t *big.Int = big.NewInt(0)

		n.SetInt64(0)

		for _, r := range revr(s) {
			// n += (m * i)
			t.SetInt64(int64(alpha.PosOf(r)))

			t.Mul(t, m)
			n.Add(n, t)

			// m *= rad
			t.SetInt64(int64(alpha.Len()))
			m.Mul(m, t)
		}
	}

	return n
}

// reverse the bytes in a slice. @d and @s may be the
// same slice but may not otherwise overlap
func revb(d, s []byte) {
	var i, j int
	for i, j = 0, len(s)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = s[j], s[i]
	}
	if i == j {
		d[i] = s[j]
	}
}

func revr(s []rune) []rune {
	var i, j int
	d := make([]rune, len(s))
	for i, j = 0, len(s)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = s[j], s[i]
	}
	if i == j {
		d[i] = s[j]
	}
	return d
}
