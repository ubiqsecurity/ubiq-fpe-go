package ubiq

import (
	"testing"
)

func TestNewFFXKeyLength(t *testing.T) {
	var err error
	var key []byte

	var bad_lengths []int = []int{15, 23, 26, 30, 33, 64}
	var good_lengths []int = []int{16, 24, 32}

	twk := make([]byte, 4)

	for _, len := range bad_lengths {
		key = make([]byte, len)
		_, err = newFFX(key, twk, 1024, 0, 0, 10)
		if err == nil {
			t.FailNow()
		}
	}

	for _, len := range good_lengths {
		key = make([]byte, len)
		_, err = newFFX(key, twk, 1024, 0, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
	}
}
