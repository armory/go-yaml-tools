package secrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
)

func RegisterVaultConfig(vaultConfig VaultConfig) error {
	if err := validateVaultConfig(vaultConfig); err != nil {
		return fmt.Errorf("vault configuration error - %s", err)
	}
	Engines["vault"] = func(ctx context.Context, isFile bool, params string) (Decrypter, error) {
		vd := &VaultDecrypter{isFile: isFile, vaultConfig: vaultConfig}
		if err := vd.parse(params); err != nil {
			return nil, err
		}
		return vd, nil
	}
	return nil
}

type VaultConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	Url          string `json:"url" yaml:"url"`
	AuthMethod   string `json:"authMethod" yaml:"authMethod"`
	Role         string `json:"role" yaml:"role"`
	Path         string `json:"path" yaml:"path"`
	Username     string `json:"username" yaml:"username"`
	Password     string `json:"password" yaml:"password"`
	UserAuthPath string `json:"userAuthPath" yaml:"userAuthPath"`
	Namespace    string `json:"namespace" yaml:"namespace"`
	Token        string
}

type VaultSecret struct {
}

type VaultDecrypter struct {
	engine        string
	path          string
	key           string
	base64Encoded string
	isFile        bool
	vaultConfig   VaultConfig
}

type VaultClient interface {
	Write(path string, data map[string]interface{}) (*api.Secret, error)
	Read(path string) (*api.Secret, error)
}

func (decrypter *VaultDecrypter) Decrypt() (string, error) {
	if decrypter.vaultConfig.Token == "" {
		err := decrypter.fetchToken()
		if err != nil {
			return "", err
		}
	}
	secret, err := decrypter.fetchSecret()
	if err != nil && strings.Contains(err.Error(), "403") {
		// get new token and retry in case our saved token is no longer valid
		err := decrypter.fetchToken()
		if err != nil {
			return "", err
		}
		secret, err = decrypter.fetchSecret()
	}
	if err != nil || !decrypter.isFile {
		return secret, err
	}
	return ToTempFile([]byte(secret))
}

func (v *VaultDecrypter) IsFile() bool {
	return v.isFile
}

func (v *VaultDecrypter) parse(params string) error {
	tokens := strings.Split(params, "!")
	for _, element := range tokens {
		kv := strings.Split(element, ":")
		if len(kv) == 2 {
			switch kv[0] {
			case "e":
				v.engine = kv[1]
			case "p", "n":
				v.path = kv[1]
			case "k":
				v.key = kv[1]
			case "b":
				v.base64Encoded = kv[1]
			}
		}
	}

	if v.engine == "" {
		return fmt.Errorf("secret format error - 'e' for engine is required")
	}
	if v.path == "" {
		return fmt.Errorf("secret format error - 'p' for path is required (replaces deprecated 'n' param)")
	}
	if v.key == "" {
		return fmt.Errorf("secret format error - 'k' for key is required")
	}
	return nil
}

func validateVaultConfig(vaultConfig VaultConfig) error {
	if (VaultConfig{}) == vaultConfig {
		return fmt.Errorf("vault secrets not configured in service profile yaml")
	}
	if vaultConfig.Enabled == false {
		return fmt.Errorf("vault secrets disabled")
	}
	if vaultConfig.Url == "" {
		return fmt.Errorf("vault url required")
	}
	if vaultConfig.AuthMethod == "" {
		return fmt.Errorf("auth method required")
	}

	switch vaultConfig.AuthMethod {
	case "TOKEN":
		if vaultConfig.Token == "" {
			envToken := os.Getenv("VAULT_TOKEN")
			if envToken == "" {
				return fmt.Errorf("VAULT_TOKEN environment variable not set")
			}
		}
	case "KUBERNETES":
		if vaultConfig.Path == "" || vaultConfig.Role == "" {
			return fmt.Errorf("path and role both required for Kubernetes auth method")
		}
	case "USERPASS":
		if vaultConfig.Username == "" || vaultConfig.Password == "" || vaultConfig.UserAuthPath == "" {
			return fmt.Errorf("username, password and userAuthPath are required for user/password auth method")
		}
	default:
		return fmt.Errorf("unknown Vault secrets auth method: %q", vaultConfig.AuthMethod)
	}

	return nil
}

func (decrypter *VaultDecrypter) fetchToken() error {
	var token string
	var err error

	switch decrypter.vaultConfig.AuthMethod {
	case "TOKEN":
		token = os.Getenv("VAULT_TOKEN")
		if token == "" {
			return fmt.Errorf("VAULT_TOKEN environment variable not set")
		}
	case "KUBERNETES":
		client, err := decrypter.getVaultClient()
		if err != nil {
			return err
		}
		token, err = decrypter.fetchServiceAccountToken(client, ioutil.ReadFile)
	case "USERPASS":
		client, err := decrypter.getVaultClient()
		if err != nil {
			return err
		}
		token, err = decrypter.fetchUserPassToken(client)
	default:
		return fmt.Errorf("unknown Vault secrets auth method: %q", decrypter.vaultConfig.AuthMethod)
	}

	if err != nil {
		return fmt.Errorf("error fetching vault token - %s", err)
	}
	decrypter.vaultConfig.Token = token
	return nil
}

func (decrypter *VaultDecrypter) getVaultClient() (VaultClient, error) {
	client, err := decrypter.newAPIClient()
	if err != nil {
		return nil, err
	}
	return client.Logical(), nil
}

func (decrypter *VaultDecrypter) newAPIClient() (*api.Client, error) {
	client, err := api.NewClient(&api.Config{
		Address: decrypter.vaultConfig.Url,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching vault client: %s", err)
	}
	if decrypter.vaultConfig.Namespace != "" {
		client.SetNamespace(decrypter.vaultConfig.Namespace)
	}
	if decrypter.vaultConfig.Token != "" {
		client.SetToken(decrypter.vaultConfig.Token)
	}
	return client, nil
}

// define a file reader function so we can test kubernetes auth
type fileReader func(string) ([]byte, error)

func (decrypter *VaultDecrypter) fetchServiceAccountToken(client VaultClient, fileReader fileReader) (string, error) {
	tokenBytes, err := fileReader("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("error reading service account token: %s", err)
	}
	token := string(tokenBytes)

	data := map[string]interface{}{
		"role": decrypter.vaultConfig.Role,
		"jwt":  token,
	}
	loginPath := "auth/" + decrypter.vaultConfig.Path + "/login"
	log.Infof("logging into vault with KUBERNETES auth at: %s", loginPath)
	secret, err := client.Write(loginPath, data)
	if err != nil {
		return "", fmt.Errorf("error logging into vault using kubernetes auth: %s", err)
	}

	return secret.Auth.ClientToken, nil
}

func (decrypter *VaultDecrypter) fetchUserPassToken(client VaultClient) (string, error) {

	data := map[string]interface{}{
		"password": decrypter.vaultConfig.Password,
	}

	loginPath := "auth/" + decrypter.vaultConfig.UserAuthPath + "/login/" + decrypter.vaultConfig.Username
	log.Infof("logging into vault with USERPASS auth at: %s", loginPath)
	secret, err := client.Write(loginPath, data)
	if err != nil {
		return "", fmt.Errorf("error logging into vault using user/password auth: %s", err)
	}

	return secret.Auth.ClientToken, nil
}

func (decrypter *VaultDecrypter) fetchSecret() (string, error) {
	client, err := decrypter.getVaultClient()
	if err != nil {
		return "", fmt.Errorf("error fetching vault client - %s", err)
	}

	path := decrypter.engine + "/" + decrypter.path
	log.Debugf("attempting to read secret at KV v1 path: %s", path)
	secretMapping, err := client.Read(path)
	if err != nil {
		if strings.Contains(err.Error(), "invalid character '<' looking for beginning of value") {
			// some connection errors aren't properly caught, and the vault client tries to parse <nil>
			return "", fmt.Errorf("error fetching secret from vault - check connection to the server: %s",
				decrypter.vaultConfig.Url)
		}
		return "", fmt.Errorf("error fetching secret from vault: %s", err)
	}

	warnings := secretMapping.Warnings
	if warnings != nil {
		for i := range warnings {
			if strings.Contains(warnings[i], "Invalid path for a versioned K/V secrets engine") {
				// try again using K/V v2 path
				path = decrypter.engine + "/data/" + decrypter.path
				log.Debugf("attempting to read secret at KV v2 path: %s", path)
				secretMapping, err = client.Read(path)
				if err != nil {
					return "", fmt.Errorf("error fetching secret from vault: %s", err)
				} else if secretMapping == nil {
					return "", fmt.Errorf("couldn't find vault path %s under engine %s", decrypter.path, decrypter.engine)
				}
				break
			}
		}
	}

	if secretMapping != nil {
		mapping := secretMapping.Data
		if data, ok := mapping["data"]; ok { // one more nesting of "data" if using K/V v2
			if submap, ok := data.(map[string]interface{}); ok {
				mapping = submap
			}
		}

		decrypted, ok := mapping[decrypter.key].(string)
		if !ok {
			return "", fmt.Errorf("error fetching secret at engine: %s, path: %s and key %s", decrypter.engine, decrypter.path, decrypter.key)
		}
		log.Debugf("successfully fetched secret")
		return decrypted, nil
	}

	return "", nil
}

func DecodeVaultConfig(vaultYaml map[interface{}]interface{}) (*VaultConfig, error) {
	var cfg VaultConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &cfg,
		WeaklyTypedInput: true,
	})
	if err != nil {
		return nil, err
	}

	if err := decoder.Decode(vaultYaml); err != nil {
		return nil, err
	}

	return &cfg, nil
}
