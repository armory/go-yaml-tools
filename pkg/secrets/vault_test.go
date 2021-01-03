package secrets

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

type MockVaultClient struct {
	mock.Mock
	token         string
	writeResponse *api.Secret
	writeErr      error
	readErr       error
	readWarnings  []string
	readData      map[string]interface{}
}

func (m *MockVaultClient) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	m.Called(path, data)
	return m.writeResponse, m.writeErr
}

func (m *MockVaultClient) Read(path string) (*api.Secret, error) {
	m.Called(path)
	return &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken: m.token,
		},
		Data:     m.readData,
		Warnings: m.readWarnings,
	}, nil
}

func TestUserPassAuth(t *testing.T) {
	cases := map[string]struct {
		config       VaultConfig
		client       *MockVaultClient
		expectedPath string
		expectedData map[string]interface{}
		expectError  bool
	}{
		"happy path": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "user",
				Password:     "password",
				UserAuthPath: "path",
			},
			client: &MockVaultClient{
				token: "my-token",
				writeResponse: &api.Secret{
					Auth: &api.SecretAuth{
						ClientToken: "my-token",
					},
				},
			},
			expectedPath: "auth/path/login/user",
			expectedData: map[string]interface{}{"password": "password"},
			expectError:  false,
		},
		"error from client gets returned": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "user",
				Password:     "password",
				UserAuthPath: "path",
			},
			client: &MockVaultClient{
				token:    "",
				writeErr: errors.New("some error"),
			},
			expectedPath: "auth/path/login/user",
			expectedData: map[string]interface{}{"password": "password"},
			expectError:  true,
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			c.client.On("Write", c.expectedPath, c.expectedData).Return(c.client.writeResponse, c.client.writeErr)

			d := &VaultDecrypter{
				vaultConfig: c.config,
			}
			token, err := d.fetchUserPassToken(c.client)
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.client.token, token)

			// assert Write() method called with expected arguments
			c.client.AssertExpectations(t)
		})
	}
}

var mockJwt = "mock-k8s-token"

func mockFileReader(filename string) ([]byte, error) {
	return []byte(mockJwt), nil
}

func TestKubernetesAuth(t *testing.T) {
	cases := map[string]struct {
		config        VaultConfig
		client        *MockVaultClient
		expectedPath  string
		expectedData  map[string]interface{}
		expectedToken string
		expectError   bool
	}{
		"happy path": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "KUBERNETES",
				Role:       "role",
				Path:       "kubernetes",
			},
			client: &MockVaultClient{
				token: "my-initial-token",
				writeResponse: &api.Secret{
					Auth: &api.SecretAuth{
						ClientToken: "vault-token",
					},
				},
			},
			expectedPath: "auth/kubernetes/login",
			expectedData: map[string]interface{}{
				"role": "role",
				"jwt":  mockJwt,
			},
			expectedToken: "vault-token",
			expectError:   false,
		},
		"error from client gets returned": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "KUBERNETES",
				Role:       "role",
				Path:       "kubernetes",
			},
			client: &MockVaultClient{
				token:    "",
				writeErr: errors.New("some error"),
			},
			expectedPath: "auth/kubernetes/login",
			expectedData: map[string]interface{}{
				"role": "role",
				"jwt":  mockJwt,
			},
			expectError: true,
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			c.client.On("Write", c.expectedPath, c.expectedData).Return(c.client.writeResponse, c.client.writeErr)

			d := &VaultDecrypter{
				vaultConfig: c.config,
			}
			token, err := d.fetchServiceAccountToken(c.client, mockFileReader)
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.expectedToken, token)

			// assert Write() method called with expected arguments
			c.client.AssertExpectations(t)
		})
	}
}

func TestValidateVaultConfig(t *testing.T) {
	cases := map[string]struct {
		config  VaultConfig
		wantErr bool
	}{
		"if Token, we don't need to look in env var": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "TOKEN",
				Role:       "",
				Path:       "",
				Token:      "s.123123123",
			},
			wantErr: false,
		},
		"kubernetes auth happy path": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "KUBERNETES",
				Role:       "role",
				Path:       "path",
			},
			wantErr: false,
		},
		"kubernetes auth missing role": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "KUBERNETES",
				Role:       "",
				Path:       "path",
			},
			wantErr: true,
		},
		"kubernetes auth missing path": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "KUBERNETES",
				Role:       "role",
				Path:       "",
			},
			wantErr: true,
		},
		"userpass auth happy path": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "user",
				Password:     "password",
				UserAuthPath: "path",
			},
			wantErr: false,
		},
		"userpass auth missing user": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "",
				Password:     "password",
				UserAuthPath: "path",
			},
			wantErr: true,
		},
		"userpass auth missing password": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "user",
				Password:     "",
				UserAuthPath: "path",
			},
			wantErr: true,
		},
		"userpass auth missing userAuthPath": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "user",
				Password:     "password",
				UserAuthPath: "",
			},
			wantErr: true,
		},
		"unknown auth method returns error": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "UNKNOWN",
			},
			wantErr: true,
		},
	}

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			if err := validateVaultConfig(c.config); (err != nil) != c.wantErr {
				t.Errorf("validateVaultConfig() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestNoSecret(t *testing.T) {
	notASecret := "notASecret"
	eng, err := NewDecrypter(context.TODO(), notASecret)
	assert.Nil(t, err)

	unchanged, _ := eng.Decrypt()
	assert.Equal(t, notASecret, unchanged)
}

func TestNoVaultConfig(t *testing.T) {
	e := Engines["vault"]
	delete(Engines, "vault")
	decrypter, err := NewDecrypter(context.TODO(), "encrypted:vault!e:secret!n:test-secret!k:foo")
	assert.NotNil(t, err)
	assert.Nil(t, decrypter)
	Engines["vault"] = e
}

func TestNewClient(t *testing.T) {
	cases := map[string]struct {
		cfg VaultConfig
	}{
		"with namespace": {
			cfg: VaultConfig{
				Enabled:    true,
				Url:        "http://127.0.0.1:8200",
				AuthMethod: "KUBERNETES",
				Namespace:  "my-namespace",
				Role:       "my-role",
				Path:       "my-path",
				Token:      "my-token",
			},
		},
		"no namespace": {
			cfg: VaultConfig{
				Enabled:    true,
				Url:        "http://127.0.0.1:8200",
				AuthMethod: "KUBERNETES",
				Namespace:  "",
				Role:       "my-role",
				Path:       "my-path",
				Token:      "my-other-token",
			},
		},
		"no token": {
			cfg: VaultConfig{
				Enabled:    true,
				Url:        "http://127.0.0.1:8200",
				AuthMethod: "KUBERNETES",
				Role:       "my-role",
				Path:       "my-path",
				Token:      "",
			},
		},
	}

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			d := VaultDecrypter{
				vaultConfig: c.cfg,
			}

			client, err := d.newAPIClient()
			assert.Nil(t, err)
			assert.Equal(t, c.cfg.Token, client.Token())
			assert.Equal(t, c.cfg.Url, client.Address())

			if c.cfg.Namespace != "" {
				headers := client.Headers()
				assert.NotNil(t, headers)
				assert.Equal(t, c.cfg.Namespace, headers.Get(consts.NamespaceHeaderName))
			}
		})
	}
}

func TestParseVaultSecret(t *testing.T) {
	cases := map[string]struct {
		params            string
		expectedDecrypter *VaultDecrypter
		shouldError       bool
	}{
		"standard syntax": {
			params: "e:engine!p:path!k:key",
			expectedDecrypter: &VaultDecrypter{
				engine: "engine",
				path:   "path",
				key:    "key",
			},
			shouldError: false,
		},
		"with deprecated n param": {
			params: "e:engine!n:path!k:key",
			expectedDecrypter: &VaultDecrypter{
				engine: "engine",
				path:   "path",
				key:    "key",
			},
			shouldError: false,
		},
		"with binary file flag": {
			params: "e:engine!p:path!k:key!b:true",
			expectedDecrypter: &VaultDecrypter{
				engine:        "engine",
				path:          "path",
				key:           "key",
				base64Encoded: "true",
			},
			shouldError: false,
		},
		"missing engine": {
			params: "n:path!k:key",
			expectedDecrypter: &VaultDecrypter{
				path: "path",
				key:  "key",
			},
			shouldError: true,
		},
		"missing path": {
			params: "e:engine!k:key",
			expectedDecrypter: &VaultDecrypter{
				engine: "engine",
				key:    "key",
			},
			shouldError: true,
		},
		"missing key": {
			params: "e:engine!p:path",
			expectedDecrypter: &VaultDecrypter{
				engine: "engine",
				path:   "path",
			},
			shouldError: true,
		},
	}

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			v := &VaultDecrypter{}
			err := v.parse(c.params)
			assert.Equal(t, c.shouldError, err != nil)
			assert.EqualValues(t, c.expectedDecrypter, v)
		})
	}
}
