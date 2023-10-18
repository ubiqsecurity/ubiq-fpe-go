package ubiq

import (
	"errors"
	"golang.org/x/exp/slices"
)

const (
	defaultAlphabetStr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var defaultAlphabet, _ = NewAlphabet(defaultAlphabetStr)

type letter struct {
	val rune
	pos int
}

type Alphabet struct {
	def bool

	by_pos []rune
	by_val []letter
}

func NewAlphabet(s string) (Alphabet, error) {
	self := Alphabet{
		by_pos: []rune(s),
	}

	self.by_val = make([]letter, len(self.by_pos))
	for i, v := range self.by_pos {
		self.by_val[i] = letter{
			val: v,
			pos: i,
		}
	}
	slices.SortFunc(self.by_val,
		func(a, b letter) int {
			return int(a.val) - int(b.val)
		})

	for i := 1; i < len(self.by_val); i++ {
		if self.by_val[i] == self.by_val[i-1] {
			return Alphabet{}, errors.New(
				"duplicate letters found in alphabet")
		}
	}

	self.def = (len(s) <= len(defaultAlphabetStr)) &&
		(s == defaultAlphabetStr[:len(s)])

	return self, nil
}

func (self *Alphabet) Len() int {
	return len(self.by_pos)
}

func (self *Alphabet) IsDef() bool {
	return self.def
}

func (self *Alphabet) PosOf(c rune) int {
	idx, ok := slices.BinarySearchFunc(self.by_val, c,
		func(a letter, b rune) int {
			return int(a.val) - int(b)
		})
	if !ok {
		return -1
	}

	return self.by_val[idx].pos
}

func (self *Alphabet) ValAt(i int) rune {
	return self.by_pos[i]
}
