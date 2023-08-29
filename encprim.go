// Package encprim provides simple encryption primitives that are easy to use and hard to get wrong.
// encprim provides one tool that can be used to securely encrypt, decrypt, and generate
// encryption keys. The default behavior is set up in such a way that when using the library
// as simply as possible is as secure as possible. When needed each function will contain
// warnings for behavior that is not default and which may cause the output to be insecure
// or less secure.
package encprim

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/scrypt"
)

const (
	AESNonceLength   = 16     // the unique nonce will always be this size (128 bits).
	AESKeyLength     = 32     // the aes key size will always be this size (256 bits).
	ScryptSaltLength = 16     // the scrypt salt size will always be this size (128 bits).
	ScryptN          = 131072 // the CPU/memory cost parameter for scrypt.
	ScryptR          = 8      // the block size parameter for scrypt.
	ScryptP          = 1      // the parallelization parameter for scrypt.
	MinimumPassword  = 10     // this is the minimum number of bytes accepted for key derivation.
)

// Key provides a structured representation of an encryption/decryption key.
// NOTE: NEVER REUSE A SALT FOR ENCRYPTION!
//
// A salt must always be cryptographically random when derivation for encryption is performed
// otherwise it greatly reduces the security afforded by the operation. The ability
// to specify a salt when deriving is only provided to ease the ability to test
// the code predictably and should never appear in use outside of testing.
type Key struct {
	Key  [AESKeyLength]byte     // the key used for encryption/decryption operations.
	Salt [ScryptSaltLength]byte // the salt used to derive the key (encryption only)
}

// CipherBlock provides a structured representation of a ciphertext and it's parts.
// NOTE: When encryption is performed a random nonce is generated. This must be included
// with the ciphertext in order for decryption to be performed successfully.
//
// It is a good idea, if you are using a shared password/passphrase, to include the random
// salt that was used to generate the key as well so that the recipient/user can use the same
// password to generate the same key needed to perform the decryption of the ciphertext.
type CipherBlock struct {
	Bytes []byte               // an arbitrary slice of bytes representing a ciphertext.
	Nonce [AESNonceLength]byte // the nonce that was generated and used when performing encryption.
}

// NewCipherBlock creates a new encprim.CipherBlock given a ciphertext and a nonce.
func NewCipherBlock(bytes []byte, nonce []byte) (CipherBlock, error) {
	nonceArray := [AESNonceLength]byte{}

	if len(nonce) != AESNonceLength {
		err := fmt.Errorf("nonce length incorrect. expected %d got %d", AESNonceLength, len(nonce))
		return CipherBlock{}, err
	}

	copy(nonceArray[:], nonce)

	return CipherBlock{bytes, nonceArray}, nil
}

// generateUniqueBytes generates a cryptographically random set of AESNonceLength bytes.
// This function is not exported because you should almost never be generating your own
// salts or nonces as this library is designed to do that for you to minimize the possibility
// of salt/nonce reuse.
func generateUniqueBytes() ([AESNonceLength]byte, error) {
	var rbytes [AESNonceLength]byte

	bytes := make([]byte, AESNonceLength)
	if _, err := rand.Read(bytes); err != nil {
		err = fmt.Errorf("error generating random bytes: %s", err)
		return [AESNonceLength]byte{}, err
	}

	copy(rbytes[:], bytes)
	return rbytes, nil
}

// newAESGCMCipher sets up a cipher structure for 256-bit AES-GCM operations.
// This function is not exported because you should be using the primitives provided
// rather than trying to do this yourself. That is why you are using a library isn't it?
func newAESGCMCipher(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("error creating new cipher: %s", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		err = fmt.Errorf("error setting up GCM mode: %s", err)
		return nil, err
	}

	return gcm, nil
}

// deriveKey takes a password and a salt and uses it to derive a cryptographic key.
// This function is not exported because it allows you to specify a salt for key derivation
// and this is only optimal for decryption and should never be done when deriving a key for
// encryption as one will securely be generated for each encryption option. Instead, another
// function with a more meaningful name (e.g. RederiveKey) is used to differentiate the
// derivation of an encryption key from the rederivation of a key for decryption.
func deriveKey(password string, inSalt [ScryptSaltLength]byte) ([]byte, error) {
	if len(password) < MinimumPassword {
		err := fmt.Errorf("password length is too small: %d bytes required", MinimumPassword)
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), inSalt[:], ScryptN, ScryptR, ScryptP, AESKeyLength)
	if err != nil {
		err = fmt.Errorf("error generating key: %s", err)
		return nil, err
	}

	return key, nil
}

// FromString provides a way to generate a new key from a password/passphrase.
// This function should only ever be used when deriving a key for encryption. To
// rederive a key from a known salt and a pre-shared or otherwise already known
// password/passphrase please use the RederiveKey method. The salt does not need
// to be kept secret.
func (k *Key) FromString(password string) error {
	salt, err := generateUniqueBytes()
	if err != nil {
		err = fmt.Errorf("error generating unique salt: %s", err)
		return err
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		err = fmt.Errorf("error deriving a key from password: %s", err)
		return err
	}

	copy(k.Key[:], key)
	k.Salt = salt

	return nil
}

// RederiveKey provides a way to rederive a key from a known salt and a known password/passphrase/
// This function SHOULD ONLY BE USED FOR DECRYPTION as reusing a salt reduces the security
// of the generated key. If you are using this for encryption outside unit testing you
// need to stop and rethink what you are doing because I promise you that you don't want
// to do this. Just use a new salt for every new key unless you are trying to rederive a key
// from a known password/passphrase and a salt.
func (k *Key) RederiveKey(password string, salt []byte) error {
	var saltArray [ScryptSaltLength]byte

	if len(salt) != ScryptSaltLength {
		err := fmt.Errorf("incorrect salt length. Expected %d got %d", ScryptSaltLength, len(salt))
		return err
	}

	copy(saltArray[:], salt)

	key, err := deriveKey(password, saltArray)
	if err != nil {
		err = fmt.Errorf("error rederiving key: %s", err)
		return err
	}

	copy(k.Key[:], key)
	k.Salt = saltArray

	return nil
}

// Encrypt provides a way to encrypt an arbitrary slice of bytes using a given key.
// The key should be derived from the FromString function and NEVER from the
// RederiveKey function!
func (k *Key) Encrypt(plaintext []byte) (CipherBlock, error) {
	nilBlock := CipherBlock{}

	nonce, err := generateUniqueBytes()
	if err != nil {
		err = fmt.Errorf("error generating unique nonce: %s", err)
		return nilBlock, err
	}

	gcm, err := newAESGCMCipher(k.Key[:])
	if err != nil {
		err = fmt.Errorf("error initializing new cipher: %s", err)
		return nilBlock, err
	}

	ciphertext := gcm.Seal(nil, nonce[:], plaintext, nil)

	return CipherBlock{ciphertext, nonce}, nil
}

// Decrypt provides a way to decrypt an arbitrary slice of bytes given a known nonce.
// The nonce provided should always be the nonce that was used to encrypt the ciphertext
// otherwise this function will fail to produce a plaintext and will instead return an error.
// It is important that the nonce be included when distributing the ciphertext and the nonce
// does not need to be kept secret and can be shared in the clear.
func (k *Key) Decrypt(ciphertext CipherBlock) ([]byte, error) {
	gcm, err := newAESGCMCipher(k.Key[:])
	if err != nil {
		err = fmt.Errorf("error initializing new cipher: %s", err)
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ciphertext.Nonce[:], ciphertext.Bytes[:], nil)
	if err != nil {
		err = fmt.Errorf("error decrypting: %s")
		return nil, err
	}

	return plaintext, nil
}
