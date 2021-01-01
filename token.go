package crypto

import (
	"time"
)

// Token vs Certificate?
type Token struct {
	Keypair   *Keypair
	ExpiresAt time.Time
	Message   string
}

// TODO: Token privdes a cryptographically secure access, thats not the same as
//       a child key. A child key can sign, generate, and encrypt messages. But
//       a token can only permit access. The message of the token is to allow
//       developers to define permission or other functionality of the token.
