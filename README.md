# encprim
This package provides a high-level set of encryption primitives which can be used in their default configuration to securely derive encryption/decryption keys from a password or passphrase as well as to encrypt or decrypt data. The goal of this package is to ensure that anyone who wants access to secure authenticated encryption can have it without needing to worry about the details or making mistakes that ultimately compromise the security of their efforts. This code is open source so that you can learn from it if you need to incorporate similar concepts into your own code as well as to show that I have nothing to hide in making this software.

## Installation
This package can be installed by running `go get` as follows:

```bash
go get github.com/AbishYoung/encprim
```

## Usage
This package is made to be as user-friendly as possible so below are a few helpful examples of how to use what is provided.

### Deriving a new key
```go
import (
	"github.com/AbishYoung/encprim"
)

func main() {
	// password must be as long or longer than encprim.MinimumPassword (10 bytes)
	password := "password123" // clearly a fake password never use this
	key := encprim.Key{}      // create a new key
	err := key.FromString(password)
	if err != nil {
		panic("Uh oh something went wrong!")
    }
	
	// key is now populated with a new encryption key as well as a random salt!
	// if you plan to rederive the same key at a later point, whether you want to only
	// use a password or if you are sending a ciphertext to another party and have only
	// pre-shared a password, then you will need to preserve the salt. The salt is not
	// private and can be shared in the open, but you will need it in order to derive the
	// same key from the same password.
}
```

### Rederiving an encryption key
**THIS SHOULD ONLY BE DONE WHEN DECRYPTING AND NEVER WHEN ENCRYPTING**

```go
import (
	"github.com/AbishYoung/encprim"
)

func main() {
	// the password should never be stored alongside the ciphertext. It is, obviously, a secret.
	password := []byte{"password123"} // again, not a real password. Never use this.
	
	// the salt is not a secret and should be stored alongside the ciphertext if you plan on
	// deriving the same key that was used to encrypt from only a password/passphrase.
	salt := // some unique salt that you obtained. For a good price perhaps?
	
	// new key struct
	key := encprim.Key{}
	err := key.RederiveKey(password, salt)
	if err != nil {
		panic("Uh oh something went wrong!")
    }
	
	// key should now be populated with the same data as was used to originally derive the
	// encryption key.
}
```

### Encrypting using a derived key
```go
import (
	"github.com/AbishYoung/encprim"
)

func main() {
	// This can be generated using the Deriving a new key example.
	key := // some key struct
	ciphertext, err := key.Encrypt([]byte("Hello, World!"))
	if err != nil {
		panic("Uh oh something went wrong!")
    }
	
	// ciphertext will now be populated with a new encprim.CipherBlock struct.
	// The encrypted data can then be accessed through ciphertext.Bytes and the unique
	// nonce can be accessed through ciphertext.Nonce. Like the salt in the Deriving a new
	// key example it must be preserved for decryption of the ciphertext to be successful. 
	// The nonce is not private and can be shared in the open.
}
```

### Decrypting using a derived key
```go
import (
	"github.com/AbishYoung/encprim"
)

func main() {
	// These values should either be stored alongside each other or sent alongside each other.
	ciphertext := // some arbitrary slice of bytes that constitutes the ciphertext.
	nonce :=      // a slice of bytes that represent the nonce used to encrypt (len(nonce) == encprim.AESNonceLength).
	key :=        // the key derived using the Rederive encryption key example.
	
	// Create a new encprim.CipherBlock
	block, err := encprim.NewCipherBlock(ciphertext, nonce)
	if err != nil {
		panic("The nonce is probably not %d bytes...", encprim.AESNonceLength)
    }
	
	plaintext, err := key.Decrypt(block)
	if err != nil {
		panic("Uh oh something went wrong!")
    }
	
	// plaintext should now hold a byte slice populated with the decrypted plaintext which
	// can then be used how-so-ever you desire.
}
```

## License
This project is licensed under the MIT OSS license. For more information see the [LICENSE.md](LICENSE.md) file.