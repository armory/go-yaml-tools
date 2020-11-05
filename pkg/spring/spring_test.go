package spring

import (
	"bytes"
	"context"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

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

func TestGetYAMLConfigFilesToo(t *testing.T) {
	wd, _ := os.Getwd()
	configDir := fmt.Sprintf("%s/../../test/springconf/", wd)

	propNames := []string{"clouddriver"}
	envPairs := []string{"SPRING_PROFILES_ACTIVE=armory,local"}
	props, _ := LoadProperties(propNames, configDir, envPairs)
	clouddriver := props["clouddriver"].(map[string]interface{})
	fmt.Println(clouddriver[""])
	assert.Equal(t, "true", clouddriver["testValue"])
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
	defer func() {
		fs = afero.NewOsFs()
	}()

	props, err := LoadDefault([]string{"spinnaker"})
	assert.Nil(t, err)
	spinnaker := props["spinnaker"].(map[string]interface{})
	assert.Equal(t, "false", spinnaker["something"])
}

func TestDefaultsWithMultipleProfiles(t *testing.T) {
	mockSpinnakerFile := `
services:
  front50:
    storage_bucket: mybucket2
`
	mockSpinnakerArmoryFile := `
services:
  front50:
    storage_bucket: mybucket
`
	mockFs := afero.NewMemMapFs()
	mockFs.MkdirAll("/home/spinnaker/config", 0755)
	afero.WriteFile(mockFs, "/home/spinnaker/config/spinnaker.yml", []byte(mockSpinnakerFile), 0644)
	afero.WriteFile(mockFs, "/home/spinnaker/config/spinnaker-armory.yml", []byte(mockSpinnakerArmoryFile), 0644)
	// Set the file system for the whole package. If we run into collisions we
	// might need to move this into a struct instead of keeping it at the
	// package level.
	fs = mockFs
	defer func() {
		fs = afero.NewOsFs()
	}()
	os.Setenv("SPINNAKER_DEFAULT_STORAGE_BUCKET", "mybucket2")
	os.Setenv("ARMORYSPINNAKER_CONF_STORE_BUCKET", "mybucket")
	props, err := LoadDefault([]string{"spinnaker"})
	t.Log(props)
	assert.Nil(t, err)
	type yaml struct {
		Services struct {
			Front50 struct {
				Bucket string `json:"storage_bucket" mapstructure:"storage_bucket"`
			} `json:"front50" mapstructure:"front50"`
		} `json:"services" mapstructure:"services"`
	}
	y := yaml{}
	mapstructure.WeakDecode(props, &y)
	assert.Equal(t, "mybucket", y.Services.Front50.Bucket)
}

func TestConfigDirs(t *testing.T) {
	env := springEnv{}
	env.initialize()
	assert.Equal(t, len(env.defaultConfigDirs), 4)
}

func TestWatch(t *testing.T) {
	// We don't use the in-memory file system because we rely on watch
	dir, err := ioutil.TempDir("", "spring-test")
	if !assert.Nil(t, err) {
		return
	}

	defer os.RemoveAll(dir)

	file1 := dir + "/spinnaker.yaml"
	file2 := dir + "/gate.yml"

	assert.Nil(t, ioutil.WriteFile(file1, []byte("foo: bar"), 0644))
	assert.Nil(t, ioutil.WriteFile(file2, []byte("foo: baz"), 0644))

	ctx, cancel := context.WithCancel(context.TODO())
	env := springEnv{configDir: dir}
	c, err := loadDefaultDynamicWithEnv(env, ctx, []string{"gate"}, func(cfg map[string]interface{}, err error) {
		if ctx.Err() != nil {
			return
		}
		assert.Equal(t, "bat", cfg["foo"])
		cancel()
	})

	assert.Nil(t, err)
	assert.Equal(t, "baz", c["foo"])

	// Wait a bit to be sure the watcher is watching
	time.Sleep(500 * time.Millisecond)
	ioutil.WriteFile(file2, []byte("foo: bat"), 0644)

	for {
		select {
		case <-time.After(1 * time.Second):
			fmt.Println("time out reached")
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func TestWatchParseError(t *testing.T) {
	// We don't use the in-memory file system because we rely on watch
	dir, err := ioutil.TempDir("", "spring-test")
	if !assert.Nil(t, err) {
		return
	}

	defer os.RemoveAll(dir)

	env := springEnv{configDir: dir}
	propNames := []string{"kubesvc"}
	file3 := dir + "/kubesvc.yml"

	assert.Nil(t, ioutil.WriteFile(file3, []byte("foo: baz"), 0644))

	previousOut := logrus.StandardLogger().Out
	defer logrus.SetOutput(previousOut)
	var buf bytes.Buffer
	logrus.SetOutput(io.MultiWriter(os.Stderr, &buf))

	ctx, cancel := context.WithCancel(context.TODO())
	c, err := loadDefaultDynamicWithEnv(env, ctx, propNames, func(cfg map[string]interface{}, err error) {
		if ctx.Err() != nil {
			return
		}
		assert.Contains(t, buf.String(), "file "+file3+" had error ")
		cancel()
	})

	assert.Nil(t, err)
	assert.Equal(t, "baz", c["foo"])

	// Wait a bit to be sure the watcher is watching
	time.Sleep(500 * time.Millisecond)
	ioutil.WriteFile(file3, []byte(`
kubernetes:
  accounts:
    -name: gke_github-replication-sandbox_us-central1-c_kubesvc-testing1-dev
      kubeconfigFile: /kubeconfigfiles/kubeconfig
`), 0644)

	for {
		select {
		case <-time.After(1 * time.Second):
			fmt.Println("time out reached")
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func TestWatchSymLink(t *testing.T) {
	dir, err := ioutil.TempDir("", "spring-test")
	if !assert.Nil(t, err) {
		return
	}
	defer os.RemoveAll(dir)

	file := dir + "/gate-real.yml"
	newFile := dir + "/gate.yml"

	assert.Nil(t, ioutil.WriteFile(file, []byte("foo: bar"), 0644))
	os.Symlink(file, newFile)

	ctx, cancel := context.WithCancel(context.TODO())
	env := springEnv{configDir: dir}
	c, err := loadDefaultDynamicWithEnv(env, ctx, []string{"gate"}, func(cfg map[string]interface{}, err error) {
		if ctx.Err() != nil {
			return
		}
		assert.Equal(t, "bat", cfg["foo"])
		cancel()
	})

	assert.Nil(t, err)
	assert.Equal(t, "bar", c["foo"])

	// Wait a bit to be sure the watcher is watching
	time.Sleep(500 * time.Millisecond)
	ioutil.WriteFile(file, []byte("foo: bat"), 0644)

	for {
		select {
		case <-time.After(1 * time.Second):
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func Test_logFsStatError(t *testing.T) {
	fs := afero.NewOsFs()
	tempDir, err := afero.TempDir(fs, "/tmp", "testfstaterror")
	if !assert.NoError(t, err) {
		return
	}
	defer fs.RemoveAll(tempDir)

	previousOut := logrus.StandardLogger().Out
	defer logrus.SetOutput(previousOut)
	var buf bytes.Buffer
	logrus.SetOutput(io.MultiWriter(os.Stderr, &buf))

	a := afero.NewBasePathFs(fs, tempDir)
	_, err = a.Stat(".missingfile__")
	if !assert.True(t, os.IsNotExist(err)) {
		return
	}
	logFsStatError(err, "")
	if !assert.Len(t, buf.String(), 0) {
		return
	}

	dir := "test"
	file := "test/test"
	err = a.Mkdir(dir, 0755)
	if !assert.NoError(t, err) {
		return
	}
	f, err := a.Create(file)
	if !assert.NoError(t, err) {
		return
	}
	_ = f.Close()

	err = a.Chmod(dir, 0222)
	if !assert.NoError(t, err) {
		return
	}

	_, err = a.Stat(file)
	if !assert.Error(t, err) {
		return
	}
	logFsStatError(err, "")
	if !assert.Contains(t, buf.String(), "level=error") {
		return
	}
}

func Test_loadConfig(t *testing.T) {
	fs = afero.NewMemMapFs()
	configFile := "kubesvc.yaml"
	content := `
kubernetes:
  accounts:
    -name: gke_github-replication-sandbox_us-central1-c_kubesvc-testing1-dev
      kubeconfigFile: /kubeconfigfiles/kubeconfig
`
	var err error
	var file afero.File
	if file, err = fs.Create(configFile); !assert.NoError(t, err) {
		return
	}
	if _, err := file.WriteString(content); !assert.NoError(t, err) {
		return
	}

	// Test
	config, err := loadConfig(configFile)

	const expectedMessage = "unable to parse config file"
	if !assert.Len(t, config, 0) {
		return
	}
	if !assert.Error(t, err, "with message %q", expectedMessage) {
		return
	}
	if !assert.Contains(t, err.Error(), expectedMessage) {
		return
	}
}
