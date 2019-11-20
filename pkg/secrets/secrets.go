package secrets

import (
	"fmt"
	yamlParse "gopkg.in/yaml.v2"
	"io/ioutil"
	"reflect"
	"strings"
)

const (
	encryptedPrefix     = "encrypted"
	encryptedFilePrefix = "encryptedFile"
)

var Engines = map[string]func(map[string]string, bool) Decrypter{
	"s3":    NewS3Decrypter,
	"gcs":   NewGcsDecrypter,
	"vault": NewVaultDecrypter,
	"noop":  NewNoopDecrypter,
}

var Registry ConfigRegistry

type Decrypter interface {
	Decrypt() (string, error)
	IsFile() bool
}

type ConfigRegistry struct {
	VaultConfig VaultConfig
}

func NewDecrypter(encryptedSecret string) Decrypter {
	engine, params, isFile := parseTokens(encryptedSecret)
	decrypter, ok := Engines[engine]
	if !ok {
		return &NoopDecrypter{
			value:  encryptedSecret,
			isFile: false,
		}
	}
	return decrypter(params, isFile)
}

func parseTokens(encryptedSecret string) (string, map[string]string, bool) {
	var engine string
	params := map[string]string{}
	tokens := strings.Split(encryptedSecret, "!")
	isFile := false
	for _, element := range tokens {
		kv := strings.Split(element, ":")
		if len(kv) == 2 {
			if kv[0] == encryptedPrefix {
				engine = kv[1]
			} else if kv[1] == encryptedFilePrefix {
				engine = kv[1]
				isFile = true
			} else {
				params[kv[0]] = kv[1]
			}
		}
	}
	return engine, params, isFile
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

func ToTempFile(content []byte) (string, error) {
	f, err := ioutil.TempFile("", "secret-")
	if err != nil {
		return "", err
	}
	defer f.Close()

	f.Write([]byte(content))
	return f.Name(), nil
}
