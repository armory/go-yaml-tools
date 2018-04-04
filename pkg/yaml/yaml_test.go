package yaml

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	yaml "gopkg.in/yaml.v2"
)

func check(t *testing.T, e error) {
	if e != nil {
		t.Error(e)
	}
}

func readTestFixtures(t *testing.T, fileName string) map[string]interface{} {
	wd, _ := os.Getwd()
	spinnakerYml := fmt.Sprintf("%s/../../test/%s", wd, fileName)
	f, err := os.Open(spinnakerYml)
	check(t, err)
	s, err := ioutil.ReadAll(f)
	check(t, err)

	any := map[string]interface{}{}
	err = yaml.Unmarshal(s, &any)
	check(t, err)

	return any
}

func TestResolver(t *testing.T) {

	fileNames := []string{
		"spinnaker-armory.yml",
		// "spinnaker-local.yml",
		// "spinnaker.yml",
	}

	ymlMaps := []map[string]interface{}{}
	for idx, f := range fileNames {
		t.Log(idx)
		ymlMaps = append(ymlMaps, readTestFixtures(t, f))
	}

	envKeyPairs := []string{
		"SPINNAKER_AWS_ENABLED=true",
		"DEFAULT_DNS_NAME=mockdns.com",
		"REDIS_HOST=redishost.com",
	}

	resolved := Resolve(ymlMaps, envKeyPairs)
	t.Log(resolved)
	//simple replace
	assert.Equal(t, resolved["services.rosco.host"], "mockdns.com")
	assert.Equal(t, resolved["providers.google.enabled"], "false")

	//default when no ENV var is present
	assert.Equal(t, resolved["providers.aws.defaultRegion"], "us-west-2")

	//more complex substitution with urls
	assert.Equal(t, resolved["services.fiat.baseUrl"], "http://mockdns.com:7003")

	//empty url
	assert.Equal(t, resolved["providers.google.primaryCredentials.project"], "")
}
