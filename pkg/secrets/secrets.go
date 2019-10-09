package secrets

import (
	"fmt"
	yamlParse "gopkg.in/yaml.v2"
	"reflect"
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
	engine, params := ParseTokens(encryptedSecret)
	switch engine {
	case "s3":
		return NewS3Decrypter(params)
	case "gcs":
		return NewGcsDecrypter(params)
	case "vault":
		return NewVaultDecrypter(params)
	default:
		return &NoSecret{encryptedSecret}
	}
}

func ParseTokens(encryptedSecret string) (string, map[string]string) {
	var engine string
	params := map[string]string{}
	tokens := strings.Split(encryptedSecret, "!")
	for _, element := range tokens {
		kv := strings.Split(element, ":")
		if len(kv) == 2 {
			if kv[0] == "encrypted" {
				engine = kv[1]
			} else {
				params[kv[0]] = kv[1]
			}
		}
	}
	return engine, params
}

func parseSecretFile(fileContents []byte, key string) (string, error) {
	m := make(map[interface{}]interface{})
	if err := yamlParse.Unmarshal(fileContents, &m); err != nil {
		return "", err
	}

	for _, yamlKey := range strings.Split(key, ".") {
		switch s := m[yamlKey].(type) {
		case map[interface{}]interface{}:
			m = s
		case string:
			return s, nil
		case nil:
			return "", fmt.Errorf("error parsing secret file: couldn't find key %q in yaml", key)
		default:
			return "", fmt.Errorf("error parsing secret file: unknown type %q with value %q",
				reflect.TypeOf(s), s)
		}
	}

	return "", fmt.Errorf("error parsing secret file for key %q", key)
}
