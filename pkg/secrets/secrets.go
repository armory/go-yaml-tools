package secrets

import (
	"fmt"
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

func RegisterVaultConfig(vaultConfig VaultConfig) error {
	if err := ValidateVaultConfig(vaultConfig); err != nil {
		return fmt.Errorf("vault configuration error - %s", err)
	}
	Registry.VaultConfig = vaultConfig
	return nil
}

func NewDecrypter(encryptedSecret string) Decrypter {
	decType := strings.Split(encryptedSecret, "!")
	switch decType[0] {
	case "encrypted:s3":
		return NewS3Decrypter(encryptedSecret)
	case "encrypted:vault":
		return NewVaultDecrypter(encryptedSecret)
	default:
		return &NoSecret{encryptedSecret}
	}
}
