package spring

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubValues(t *testing.T) {
	wd, _ := os.Getwd()
	configDir := fmt.Sprintf("%s/../../test/springconf", wd)

	propNames := []string{"spinnaker", "gate"}
	envPairs := []string{"SPRING_PROFILES_ACTIVE=armory,local"}
	props, _ := LoadProperties(propNames, configDir, envPairs)
	spinnaker := props["spinnaker"].(map[string]interface{})
	assert.Equal(t, "false", spinnaker["armory"])
	assert.Equal(t, "true", spinnaker["default"])
}
