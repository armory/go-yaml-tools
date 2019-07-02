package secrets

import (
	"strings"
)

type Decrypter interface {
	Decrypt() (string, error)
}

type NoSecret struct {
	secret string
}

func (n *NoSecret) Decrypt() (string, error) {
	return n.secret, nil
}

var Registry ConfigRegistry

type ConfigRegistry struct {
	VaultConfig VaultConfig
}

func RegisterVaultConfig(vaultConfig VaultConfig) {
	Registry.VaultConfig = vaultConfig
}

func NewDecrypter(encryptedSecret string) Decrypter {
	decType := strings.Split(encryptedSecret, "!")
	switch decType[0] {
	case "encrypted:s3":
		return NewS3Decrypter(encryptedSecret)
	case "encrypted:vault":
		return getVaultDecrypter(encryptedSecret)
	default:
		return &NoSecret{encryptedSecret}
	}
}
