package yaml

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/armory/go-yaml-tools/pkg/secrets"

	"github.com/imdario/mergo"
	log "github.com/sirupsen/logrus"
)

type ObjectMap = map[interface{}]interface{}
type StringMap = map[string]string
type OutputMap = map[string]interface{}

// Resolve takes an array of yaml maps and returns a single map of a merged
// properties.  The order of `ymlTemplates` matters, it should go from lowest
// to highest precendence.
func Resolve(ymlTemplates []ObjectMap, envKeyPairs StringMap) (OutputMap, error) {
	log.Debugf("Using environ %+v\n", envKeyPairs)

	mergedMap := ObjectMap{}
	for _, yml := range ymlTemplates {
		if err := mergo.Merge(&mergedMap, yml, mergo.WithOverride); err != nil {
			log.Error(err)
		}
	}

	// unlike other secret engines, the vault config needs to be registered before it can decrypt anything
	vaultCfg, err := extractVaultConfig(mergedMap)
	if err == nil {
		if err := secrets.RegisterVaultConfig(*vaultCfg); err != nil {
			log.Errorf("Error registering vault config: %v", err)
		}
	}

	stringMap := convertToStringMap(mergedMap)

	if err := subValues(stringMap, stringMap, envKeyPairs); err != nil {
		return nil, err
	}

	return stringMap, nil
}

var EVCErrorMissingKey = errors.New("missing secrets.vault key")
var EVCErrorDecoding = errors.New("error decoding vault config")
var EVCErrorEmpty = errors.New("empty decoded vault config")

func extractVaultConfig(m ObjectMap) (*secrets.VaultConfig, error) {
	secretsMap, ok := m["secrets"].(ObjectMap)
	if !ok {
		return nil, EVCErrorMissingKey
	}
	vaultmap, ok := secretsMap["vault"].(ObjectMap)
	if !ok {
		return nil, EVCErrorMissingKey
	}
	cfg, err := secrets.DecodeVaultConfig(vaultmap)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", EVCErrorDecoding, err)
	}
	if cfg == nil {
		return nil, EVCErrorEmpty
	}
	if *cfg == (secrets.VaultConfig{}) {
		return nil, EVCErrorEmpty
	}
	return cfg, nil
}

func convertToStringMap(m ObjectMap) OutputMap {
	newMap := OutputMap{}
	var kstring string
	for k, v := range m {
		kstring = k.(string)
		convertOneValueToStringMap(v, newMap, kstring)
	}
	return newMap
}

func convertOneValueToStringMap(v interface{}, newMap OutputMap, kstring string) {
	switch v := v.(type) {
	case ObjectMap:
		newMap[kstring] = convertToStringMap(v)
	case []interface{}:
		for i := range v {
			converOneArrayToStringMap(v[:], i)
		}
		newMap[kstring] = v
	case string:
		newMap[kstring] = v
	case int:
		newMap[kstring] = strconv.Itoa(v)
	case bool:
		newMap[kstring] = strconv.FormatBool(v)
	case float64:
		newMap[kstring] = strconv.FormatFloat(v, 'g', -1, 64)
	case float32:
		newMap[kstring] = strconv.FormatFloat(float64(v), 'g', -1, 64)
	case fmt.Stringer:
		newMap[kstring] = v.String()
	default:
		newMap[kstring] = fmt.Sprintf("%v", v)
	}
}

func converOneArrayToStringMap(v []interface{}, i int) {
	switch vv := v[i].(type) {
	case ObjectMap:
		v[i] = convertToStringMap(vv)
	case []interface{}:
		for j := range v {
			converOneArrayToStringMap(vv[:], j)
		}
		v[i] = vv
	case string:
		v[i] = vv
	case int:
		v[i] = strconv.Itoa(vv)
	case bool:
		v[i] = strconv.FormatBool(vv)
	case float64:
		v[i] = strconv.FormatFloat(vv, 'g', -1, 64)
	case float32:
		v[i] = strconv.FormatFloat(float64(vv), 'g', -1, 64)
	case fmt.Stringer:
		v[i] = vv.String()
	default:
		v[i] = fmt.Sprintf("%v", vv)
	}
}

var re = regexp.MustCompile("\\$\\{(.*?)}")

func subValues(fullMap OutputMap, subMap OutputMap, env StringMap) error {
	//responsible for finding all variables that need to be substituted
	loops := 0
	for loops < len(subMap) {
		loops++
		for k, value := range subMap {
			if err := processOneSubvalue(fullMap, subMap, env, value, k); err != nil {
				return err
			}
		}
	}
	return nil
}

func processOneSubvalue(fullMap OutputMap, subMap OutputMap, env StringMap, value interface{}, k string) error {
	var secret string
	var decrypter secrets.Decrypter
	var valueBytes []byte
	switch value := value.(type) {
	case map[string]interface{}:
		err := subValues(fullMap, value, env)
		if err != nil {
			return err
		}
	case []interface{}:
		for i := 0; i < len(value); i++ {
			err := processOneSubvalueFromArray(fullMap, value[:], env, value[i], i)
			if err != nil {
				return err
			}
		}
	case string:
		if secrets.IsEncryptedSecret(value) {
			var err error
			if decrypter, err = secrets.NewDecrypter(context.TODO(), value); err != nil {
				return err
			} else if secret, err = decrypter.Decrypt(); err != nil {
				return err
			}
			subMap[k] = secret
			return nil
		}

		valueBytes = []byte(value)
		valueBytes = re.ReplaceAllFunc(valueBytes, func(key []byte) []byte {
			i := len(key) - 1
			myKey := string(key[2:i])
			return []byte(resolveSubs(fullMap, myKey, env))
		})
		value = string(valueBytes)
		subMap[k] = value
	}
	return nil
}

func processOneSubvalueFromArray(fullMap OutputMap, subslice []interface{}, env StringMap, value interface{}, k int) error {
	var secret string
	var decrypter secrets.Decrypter
	var valueBytes []byte
	switch value := value.(type) {
	case map[string]interface{}:
		err := subValues(fullMap, value, env)
		if err != nil {
			return err
		}
	case []interface{}:
		for i := 0; i < len(value); i++ {
			err := processOneSubvalueFromArray(fullMap, value[:], env, value[i], i)
			if err != nil {
				return err
			}
		}
	case string:
		if secrets.IsEncryptedSecret(value) {
			var err error
			if decrypter, err = secrets.NewDecrypter(context.TODO(), value); err != nil {
				return err
			} else if secret, err = decrypter.Decrypt(); err != nil {
				return err
			}
			subslice[k] = secret
			return nil
		}

		valueBytes = []byte(value)
		valueBytes = re.ReplaceAllFunc(valueBytes, func(key []byte) []byte {
			i := len(key) - 1
			myKey := string(key[2:i])
			return []byte(resolveSubs(fullMap, myKey, env))
		})
		value = string(valueBytes)
		subslice[k] = value
	}
	return nil
}

func resolveSubs(m map[string]interface{}, keyToSub string, env map[string]string) string {
	//this function returns array of tuples with their substituted values
	//this handles the case of multiple substitutions in a value
	//baseUrl: ${services.default.protocol}://${services.echo.host}:${services.echo.port}
	keyDefaultSplit := strings.Split(keyToSub, ":")
	subKey, defaultKey := keyDefaultSplit[0], keyDefaultSplit[0]
	if len(keyDefaultSplit) == 2 {
		defaultKey = keyDefaultSplit[1]
	}

	if v, err := valueFromFlatKey(subKey, m); err == nil {
		defaultKey = v
	} else if v, ok := env[subKey]; ok {
		defaultKey = v
	}

	return defaultKey
}

var VFFKErrorNotFound = errors.New("not found")
var VFFKErrorInvalidIntermediaryType = errors.New("expected map[string]interface{}")
var VFFKErrorInvalidLeafType = errors.New("expected string or stringer()")

func valueFromFlatKey(flatKey string, root map[string]interface{}) (string, error) {
	fields := strings.Split(flatKey, ".")
	var currVal interface{} = root
	var currMap OutputMap // pre-alloc OutputMap ref. Actually assigned & used in loop below
	var ok bool
	for i := range fields {
		if currVal == nil {
			return "", fmt.Errorf("path %q was %w", flatKey, VFFKErrorNotFound)
		}
		if currMap, ok = currVal.(OutputMap); !ok {
			return "", fmt.Errorf("path %q was of type %T, %w", strings.Join(fields[:i], "."), currVal, VFFKErrorInvalidIntermediaryType)
		}
		if currVal, ok = currMap[fields[i]]; !ok {
			return "", fmt.Errorf("path %q was %w", flatKey, VFFKErrorNotFound)
		}
	}
	switch v := currVal.(type) {
	case string:
		return v, nil
	case fmt.Stringer:
		return v.String(), nil
	case float32:
		return strconv.FormatFloat(float64(v), 'g', -1, 64), nil
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64), nil
	case int:
		return strconv.Itoa(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	default:
		return "", fmt.Errorf("path %q is type %T, %w", flatKey, v, VFFKErrorInvalidLeafType)
	}
}
