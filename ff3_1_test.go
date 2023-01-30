package ubiq

import (
	"testing"
)

func testFF3_1(t *testing.T, K, T []byte, PT, CT string, r int) {
	if len(PT) != len(CT) {
		t.FailNow()
	}

	ff3_1, err := NewFF3_1(K, T, r)
	if err != nil {
		t.Fatal(err)
	}

	out, err := ff3_1.Encrypt(PT, T)
	if err != nil {
		t.Fatal(err)
	}

	if out != CT {
		t.FailNow()
	}

	out, err = ff3_1.Decrypt(CT, T)
	if err != nil {
		t.Fatal(err)
	}

	if out != PT {
		t.FailNow()
	}
}

func TestFF3_1ACVP1(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xad, 0x41, 0xec, 0x5d, 0x23, 0x56, 0xde, 0xae,
			0x53, 0xae, 0x76, 0xf5, 0x0b, 0x4b, 0xa6, 0xd2,
		},
		[]byte{
			0xcf, 0x29, 0xda, 0x1e, 0x18, 0xd9, 0x70,
		},
		"6520935496",
		"4716569208",
		10)
}

func TestFF3_1ACVP2(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0x3c, 0x0a, 0xbb, 0x8c, 0x4d, 0x50, 0x52, 0x83,
			0x20, 0xed, 0x6e, 0xf4, 0xf5, 0x36, 0x37, 0x1c,
		},
		[]byte{
			0x2e, 0x0b, 0x7e, 0xe0, 0x1c, 0x13, 0x70,
		},
		"37411281822299620587806308530316674537844784195073078382",
		"45217408528208365340847148215470453887037524494034613315",
		10)
}

func TestFF3_1ACV3(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xf0, 0x09, 0x75, 0x94, 0x80, 0x5c, 0xf9, 0xb8,
			0x3b, 0x86, 0x5a, 0xc2, 0xe8, 0x6a, 0xaa, 0x3b,
		},
		[]byte{
			0xa8, 0x64, 0xbf, 0xdb, 0x7a, 0xb3, 0xe4,
		},
		"884423490276892452986545",
		"886740195115224033771281",
		10)
}

func TestFF3_1ACVP4(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xa4, 0xd5, 0x91, 0x50, 0xba, 0x52, 0x39, 0x29,
			0xf2, 0x53, 0x6e, 0x22, 0xdc, 0xd9, 0x83, 0x3a,
		},
		[]byte{
			0xc6, 0x18, 0xe4, 0xb9, 0xf1, 0x02, 0xa9,
		},
		"5121915885157704276490198331789119695462135673546462",
		"8700695822600163129327075842807189794897935821179979",
		10)
}

func TestFF3_1ACVP5(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0x65, 0xae, 0xc3, 0x2c, 0xd5, 0x00, 0x5e, 0x9d,
			0x4f, 0xe0, 0x33, 0x7d, 0x75, 0x0f, 0x88, 0x89,
		},
		[]byte{
			0x22, 0x56, 0x6b, 0x02, 0xce, 0x2b, 0x29,
		},
		"579835153593770625247573877144356016354",
		"139570038859733375828972899639612707646",
		10)
}

func TestFF3_1ACVP6(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xda, 0x0c, 0x33, 0x07, 0xfd, 0x18, 0x4c, 0x1e,
			0x47, 0xff, 0x9b, 0x8a, 0xcf, 0xd7, 0x53, 0x05,
		},
		[]byte{
			0xd9, 0xf1, 0xab, 0xd9, 0xc7, 0xce, 0x64,
		},
		"16554083965640402",
		"92429329291203011",
		10)
}

func TestFF3_1ACVP7(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0x96, 0x04, 0x0c, 0x3b, 0xd2, 0x8c, 0xac, 0xf5,
			0xbb, 0xc1, 0x04, 0xe1, 0x7b, 0x71, 0xc2, 0x92,
		},
		[]byte{
			0x75, 0xa8, 0x90, 0x2a, 0x2c, 0x33, 0xab,
		},
		"673355560820242081637314985809466",
		"978822369712766543147569600748825",
		10)
}

func TestFF3_1ACVP8(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0x47, 0xd6, 0xfd, 0x00, 0x7e, 0x50, 0x02, 0x42,
			0x40, 0xb5, 0xd5, 0x02, 0xdb, 0x5b, 0x4a, 0x6a,
		},
		[]byte{
			0xd3, 0x39, 0x9b, 0xf9, 0x3c, 0xc1, 0x0c,
		},
		"3136368918758657833514782148219054962724377646545",
		"8465961639246937993407777533030559401101453326524",
		10)
}

func TestFF3_1ACVP9(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xa8, 0x4b, 0xb5, 0x54, 0x85, 0x4d, 0xca, 0xb9,
			0xcb, 0xfd, 0x9e, 0x29, 0x80, 0x01, 0x51, 0x8c,
		},
		[]byte{
			0x7a, 0x77, 0x31, 0x72, 0xc3, 0xf0, 0xf1,
		},
		"082360355025",
		"901934302943",
		10)
}

func TestFF3_1ACVP10(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xa0, 0x0f, 0xce, 0xdf, 0x1c, 0xe6, 0xe3, 0x5c,
			0xf9, 0x09, 0x7e, 0x98, 0xdc, 0x4d, 0x28, 0x4d,
		},
		[]byte{
			0x00, 0x69, 0x85, 0xbc, 0x0e, 0x67, 0x2c,
		},
		"63987540055130890395",
		"73110711860320595989",
		10)
}

func TestFF3_1Ubiq1(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		"890121234567890000",
		"075870132022772250",
		10)
}

func TestFF3_1Ubiq2(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
		},
		[]byte{
			0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33,
		},
		"890121234567890000",
		"251467746185412673",
		10)
}

func TestFF3_1Ubiq3(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
		},
		[]byte{
			0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
		},
		"89012123456789abcde",
		"dwb01mx9aa2lmi3hrfm",
		36)
}

func TestFF3_1Ubiq4(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
			0x3b, 0x80, 0x6a, 0xeb, 0x63, 0x08, 0x27, 0x1f,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		"890121234567890000",
		"327701863379108161",
		10)
}

func TestFF3_1Ubiq5(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
			0x3b, 0x80, 0x6a, 0xeb, 0x63, 0x08, 0x27, 0x1f,
		},
		[]byte{
			0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33,
		},
		"890121234567890000",
		"738670454850774517",
		10)
}

func TestFF3_1Ubiq6(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
			0x3b, 0x80, 0x6a, 0xeb, 0x63, 0x08, 0x27, 0x1f,
		},
		[]byte{
			0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
		},
		"89012123456789abcde",
		"o3a1og390b5uduvwyw5",
		36)
}

func TestFF3_1Ubiq7(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
			0x3b, 0x80, 0x6a, 0xeb, 0x63, 0x08, 0x27, 0x1f,
			0x65, 0xcf, 0x33, 0xc7, 0x39, 0x1b, 0x27, 0xf7,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		"890121234567890000",
		"892299037726855422",
		10)
}

func TestFF3_1Ubiq8(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
			0x3b, 0x80, 0x6a, 0xeb, 0x63, 0x08, 0x27, 0x1f,
			0x65, 0xcf, 0x33, 0xc7, 0x39, 0x1b, 0x27, 0xf7,
		},
		[]byte{
			0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33,
		},
		"890121234567890000",
		"045013216693726967",
		10)
}

func TestFF3_1Ubiq9(t *testing.T) {
	testFF3_1(t,
		[]byte{
			0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f,
			0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
			0x3b, 0x80, 0x6a, 0xeb, 0x63, 0x08, 0x27, 0x1f,
			0x65, 0xcf, 0x33, 0xc7, 0x39, 0x1b, 0x27, 0xf7,
		},
		[]byte{
			0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72,
		},
		"89012123456789abcde",
		"0sxaooj0jjj5qqfomh8",
		36)
}
