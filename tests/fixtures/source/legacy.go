package legacy

import "crypto/des"

func block(key []byte) {
	b, _ := des.NewTripleDESCipher(key)
	_ = b
}
