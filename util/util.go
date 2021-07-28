package util

const (
	SM          = "SM"
	ED25519     = "ED25519"
	SECP256K1   = "SECP256K1"
	HASH_METHOD = SM
	SIGN_METHOD = ED25519
)

func HashIsSM() bool {
	return HASH_METHOD == SM
}

func SignIsSM() bool {
	return SIGN_METHOD == SM
}

func SignIsED() bool {
	return SIGN_METHOD == ED25519
}
