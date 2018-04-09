package spring

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	yamlParse "gopkg.in/yaml.v2"

	"github.com/armory/go-yaml-tools/pkg/yaml"
	log "github.com/sirupsen/logrus"
)

func loadConfig(configFile string) map[interface{}]interface{} {
	s := map[interface{}]interface{}{}
	if _, err := os.Stat(configFile); err == nil {
		bytes, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Errorf("Unable to open config file %s: %v", configFile, err)
			return nil
		}
		if err = yamlParse.Unmarshal(bytes, &s); err != nil {
			log.Errorf("Unable to parse config file %s: %v", configFile, err)
			return s
		}
		log.Info("Configured with settings from file: ", configFile)
	} else {
		log.Info("Config file ", configFile, " not present; falling back to default settings")
	}
	return s
}

//LoadProperties tries to do what spring properties manages by loading files
//using the right precendence and returning a merged map that contains all the
//keys and their values have been substituted for the correct value
func LoadProperties(propNames []string, configDir string, envKeyPairs []string) (map[string]interface{}, error) {
	envMap := map[string]string{}
	for _, envKeyPair := range envKeyPairs {
		keyPair := strings.Split(envKeyPair, "=")
		envMap[keyPair[0]] = keyPair[1]
	}

	profStr := envMap["SPRING_PROFILES_ACTIVE"]
	profs := strings.Split(profStr, ",")

	propMaps := []map[interface{}]interface{}{}
	//first load the main props, i.e. gate.yaml with no profile extensions
	for _, prop := range propNames {
		filePath := fmt.Sprintf("%s/%s.yml", configDir, prop)
		propMaps = append(propMaps, loadConfig(filePath))
	}

	for _, prop := range propNames {
		//we traverse the profiles array backwards for correct precedence
		for i := len(profs) - 1; i >= 0; i-- {
			p := profs[i]
			pTrim := strings.TrimSpace(p)
			filePath := fmt.Sprintf("%s/%s-%s.yml", configDir, prop, pTrim)
			propMaps = append(propMaps, loadConfig(filePath))
		}
	}
	m, err := yaml.Resolve(propMaps, envMap)
	return m, err
}
