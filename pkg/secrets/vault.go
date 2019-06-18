package secrets

import (
	"fmt"
)

type VaultSecret struct {
	engine        string
	namespace     string
	key           string
	base64Encoded bool
}

type VaultDecrypter struct {
	secretConfig string
}

func NewVaultDecrypter(secretConfig string) *VaultDecrypter {
	return &VaultDecrypter{secretConfig}
}

func (v *VaultDecrypter) Decrypt() (string, error) {
	return "", fmt.Errorf("vault secrets unsupported")
}
