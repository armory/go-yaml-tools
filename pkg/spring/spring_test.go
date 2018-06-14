package spring

import (
	"fmt"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestSubValues(t *testing.T) {
	wd, _ := os.Getwd()
	configDir := fmt.Sprintf("%s/../../test/springconf/", wd)

	propNames := []string{"spinnaker", "gate"}
	envPairs := []string{"SPRING_PROFILES_ACTIVE=armory,local"}
	props, _ := LoadProperties(propNames, configDir, envPairs)
	spinnaker := props["spinnaker"].(map[string]interface{})
	assert.Equal(t, "false", spinnaker["armory"])
	assert.Equal(t, "true", spinnaker["default"])
}

func TestDefaults(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	mockFs.MkdirAll("/home/spinnaker/config", 0755)
	mockFile := `
spinnaker:
  something: false
`
	afero.WriteFile(mockFs, "/home/spinnaker/config/spinnaker-local.yml", []byte(mockFile), 0644)
	// Set the file system for the whole package. If we run into collisions we
	// might need to move this into a struct instead of keeping it at the
	// package level.
	fs = mockFs
	props, err := LoadDefault([]string{"spinnaker"})
	assert.Nil(t, err)
	spinnaker := props["spinnaker"].(map[string]interface{})
	assert.Equal(t, "false", spinnaker["something"])
}

func TestConfigDirs(t *testing.T) {
	assert.Equal(t, len(defaultConfigDirs), 4)
}
