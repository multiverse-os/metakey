package crypto

import (
	"github.com/multiverse-os/codec"
	"github.com/multiverse-os/codec/checksum"
)

type KeyPart []byte

func AssembleKeypair(keyParts ...KeyPart) Keypair {
	var privateKey []byte
	for _, keyPart := range keyParts {
		privateKey = append(privateKey, keyPart)
	}

	keypair := Keypair{
		PrivateKey: privateKey,
		Salt:       codec.Checksum(checksum.XXH64, privateKey),
	}
	keypair.PublicKey = keypair.GeneratePublicKey
	return keypair
}
