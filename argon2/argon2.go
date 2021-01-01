package argon2

import "time"

//GenerateKey(seed string) Keypair
//GenerateRandomKey() Keypair
type Functionality interface {
	GenerateChildKey() Keypair

	Algorithm() string

	Encrypt(input []byte) ([]byte, error)
	Decrypt(input []byte) ([]byte, error)

	Sign(input []byte) ([]byte, error)
	VerifySignature(input []byte) (bool, error)

	SplitKey() []KeyPart
	AssembleKey(keyParts ...KeyPart) Keypair

	GenerateToken(expiresAt time.Time) Token
}

func DefaultParams() map[string]int {
	return map[string]int{
		"memory":     16384,
		"iterations": 3,
		"threads":    2,
		"Length":     32,
	}
}
