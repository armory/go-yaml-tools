package secrets

import (
	"strings"
)

type Decrypter interface {
	Decrypt() (string, error)
}

type NoSecret struct {
	secretConfig string
}

func (n *NoSecret) Decrypt() (string, error) {
	return n.secretConfig, nil
}

func NewDecrypter(secretConfig string) Decrypter {
	decType := strings.Split(secretConfig, "!")
	switch decType[0] {
	case "encrypted:s3":
		return NewS3Decrypter(secretConfig)
	case "encrypted:vault":
		return NewVaultDecrypter(secretConfig)
	default:
		return &NoSecret{secretConfig}
	}
}
