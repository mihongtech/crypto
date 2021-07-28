package signature

import (
	"fmt"

	"github.com/mihongtech/crypto"
	"github.com/mihongtech/crypto/ed25519"
	"github.com/mihongtech/crypto/secp256k1"
	"github.com/mihongtech/crypto/util"
)

//-------------------------------------

//var _ crypto.PrivKey = PrivKey{}

const (
	SeedSize      = 32
	SignatureSize = 64
)

var (
	PrivKeyName    = "tendermint/PrivKeyEd25519"
	PubKeyName     = "tendermint/PubKeyEd25519"
	PubKeySize     = 32
	PrivateKeySize = 64

	KeyType = "ed25519"
)

func init() {
	switch util.SIGN_METHOD {
	case util.ED25519:
		setParams(ed25519.PrivKeyName, ed25519.PubKeyName, ed25519.KeyType, ed25519.PubKeySize, ed25519.PrivateKeySize)
	case util.SECP256K1:
		setParams(secp256k1.PrivKeyName, secp256k1.PubKeyName, secp256k1.KeyType, secp256k1.PubKeySize, secp256k1.PrivKeySize)
	default:

	}

}

func setParams(privKeyName, pubKeyName, keyType string, pubKeySize int, privateKeySize int) {
	PrivKeyName = privKeyName
	PubKeyName = pubKeyName
	PubKeySize = pubKeySize
	PrivateKeySize = privateKeySize

	KeyType = keyType
}

//// PrivKey implements crypto.PrivKey.
//type PrivKey struct {
//	Key crypto.PrivKey
//}
//
//// Bytes returns the privkey byte format.
//func (privKey PrivKey) Bytes() []byte {
//	return privKey.Bytes()
//}
//
//// Sign produces a signature on the provided message.
//// This assumes the privkey is wellformed in the golang format.
//// The first 32 bytes should be random,
//// corresponding to the normal ed25519 private key.
//// The latter 32 bytes should be the compressed public key.
//// If these conditions aren't met, Sign will panic or produce an
//// incorrect signature.
//func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
//	return privKey.Sign(msg)
//}
//
//// PubKey gets the corresponding public key from the private key.
////
//// Panics if the private key is not initialized.
//func (privKey PrivKey) PubKey() crypto.PubKey {
//	return privKey.PubKey()
//}
//
//// Equals - you probably don't need to use this.
//// Runs in constant time based on length of the keys.
//func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
//	return privKey.Equals(other)
//}
//
//func (privKey PrivKey) Type() string {
//	return privKey.Type()
//}

// GenPrivKey generates a new ed25519 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() (key crypto.PrivKey) {
	switch util.SIGN_METHOD {
	case util.ED25519:
		key = ed25519.GenPrivKey()
	case util.SECP256K1:
		key = secp256k1.GenPrivKey()
	default:
	}
	return
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) (key crypto.PrivKey) {
	switch util.SIGN_METHOD {
	case util.ED25519:
		key = ed25519.GenPrivKeyFromSecret(secret)
	case util.SECP256K1:
		key = secp256k1.GenPrivKeySecp256k1(secret)
	default:
	}
	return
}

func BytesToPublicKey(pk []byte, keyType string) (key crypto.PubKey) {
	switch keyType {
	case "", ed25519.KeyType:
		key = ed25519.PubKey(pk)
	case secp256k1.KeyType:
		key = secp256k1.PubKey(pk)
	default:
		panic(fmt.Sprintf("key type %s not supported", keyType))
	}
	return
}

func IsSupportPubKeyType(pub crypto.PubKey) (supported bool) {
	switch pub.(type) {
	case ed25519.PubKey:
		supported = true
	case secp256k1.PubKey:
		supported = true
	default:

	}
	return
}

func IsSupportPrivKeyType(pub crypto.PrivKey) (supported bool) {
	switch pub.(type) {
	case ed25519.PrivKey:
		supported = true
	case secp256k1.PrivKey:
		supported = true
	default:

	}
	return
}

func IsCurrentPubKey(pub crypto.PubKey) (supported bool) {
	switch pub.(type) {
	case ed25519.PubKey:
		supported = (util.SIGN_METHOD == util.ED25519)
	case secp256k1.PubKey:
		supported = (util.SIGN_METHOD == util.SECP256K1)
	default:

	}
	return
}

func IsCurrentPrivKey(pub crypto.PrivKey) (supported bool) {
	switch pub.(type) {
	case ed25519.PrivKey:
		supported = (util.SIGN_METHOD == util.ED25519)
	case secp256k1.PrivKey:
		supported = (util.SIGN_METHOD == util.SECP256K1)
	default:

	}
	return
}

//-------------------------------------

//var _ crypto.PubKey = PubKey{}
//
//// PubKeyEd25519 implements crypto.PubKey for the Ed25519 signature scheme.
//type PubKey struct {
//	Key crypto.PubKey
//}
//// Address is the SHA256-20 of the raw pubkey bytes.
//func (pubKey PubKey) Address() crypto.Address {
//	return pubKey.Key.Address()
//}
//
//// Bytes returns the PubKey byte format.
//func (pubKey PubKey) Bytes() []byte {
//	return pubKey.Key.Bytes()
//}
//
//func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
//	return pubKey.Key.VerifySignature(msg,sig)
//}
//
//func (pubKey PubKey) String() string {
//	return fmt.Sprintf("PubKey%s{%X}", pubKey.Type(),pubKey.Bytes())
//}
//
//func (pubKey PubKey) Type() string {
//	return pubKey.Key.Type()
//}
//
//func (pubKey PubKey) Equals(other crypto.PubKey) bool {
//	return pubKey.Key.Equals(other)
//}
