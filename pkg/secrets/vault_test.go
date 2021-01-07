package secrets

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net"
	"os"
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
			d.setTokenFetcher()
			token, err := d.tokenFetcher.fetchToken(c.client)
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

			tokenFetcher := KubernetesServiceAccountTokenFetcher{
				role:       c.config.Role,
				path:       c.config.Path,
				fileReader: mockFileReader,
			}
			token, err := tokenFetcher.fetchToken(c.client)
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.expectedToken, token)

			// assert Write() method called with expected arguments
			c.client.AssertExpectations(t)
		})
	}
}

func mockEnvGetter(name string) string {
	return "mock-env-token"
}

func mockEnvFailToGetter(name string) string {
	return ""
}

func TestTokenAuth(t *testing.T) {
	cases := map[string]struct {
		expectedToken string
		expectError   bool
	}{
		"happy path": {
			expectedToken: "mock-env-token",
			expectError:   false,
		},
		"env variable not set": {
			expectedToken: "",
			expectError:   true,
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			os.Setenv("VAULT_TOKEN", c.expectedToken)
			tokenFetcher := EnvironmentVariableTokenFetcher{}
			token, err := tokenFetcher.fetchToken(nil)
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.expectedToken, token)
			os.Unsetenv("VAULT_TOKEN")

		})
	}
}

func TestValidateVaultConfig(t *testing.T) {
	cases := map[string]struct {
		config  VaultConfig
		wantErr bool
	}{
		"vault not enabled": {
			config: VaultConfig{
				Enabled:    false,
				Url:        "vault.com",
				AuthMethod: "KUBERNETES",
				Role:       "role",
				Path:       "path",
			},
			wantErr: true,
		},
		"missing URL": {
			config: VaultConfig{
				Enabled:    true,
				AuthMethod: "KUBERNETES",
				Role:       "role",
				Path:       "path"},
			wantErr: true,
		},
		"missing auth method": {
			config: VaultConfig{
				Enabled: true,
				Url:     "vault.com",
			},
			wantErr: true,
		},
		"token auth missing env variable": {
			config: VaultConfig{
				Enabled:    true,
				AuthMethod: "TOKEN",
			},
			wantErr: true,
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
		"if Token already set, we don't need to look in env var": {
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
	}

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			if err := validateVaultConfig(c.config); (err != nil) != c.wantErr {
				t.Errorf("validateVaultConfig() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestSetTokenFetcher(t *testing.T) {
	cases := map[string]struct {
		config               VaultConfig
		expectedTokenFetcher TokenFetcher
		expectError          bool
	}{
		"token auth": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "TOKEN",
			},
			expectedTokenFetcher: EnvironmentVariableTokenFetcher{},
			expectError:          false,
		},
		//"kubernetes auth": {
		//	config: VaultConfig{
		//		Enabled:    true,
		//		Url:        "vault.com",
		//		AuthMethod: "KUBERNETES",
		//		Role:       "my-role",
		//		Path:       "my-path",
		//	},
		//	expectedTokenFetcher: KubernetesServiceAccountTokenFetcher{
		//		role: "my-role",
		//		path: "my-path",
		//		fileReader: ioutil.ReadFile,
		//		//tokenFile:
		//	},
		//	expectError: false,
		//},
		"userpass auth": {
			config: VaultConfig{
				Enabled:      true,
				Url:          "vault.com",
				AuthMethod:   "USERPASS",
				Username:     "my-user",
				Password:     "my-password",
				UserAuthPath: "my-path",
			},
			expectedTokenFetcher: UserPassTokenFetcher{
				username:     "my-user",
				password:     "my-password",
				userAuthPath: "my-path",
			},
			expectError: false,
		},
		"unknown auth": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "UNKNOWN",
			},
			expectError: true,
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {

			decrypter := &VaultDecrypter{
				vaultConfig: c.config,
			}
			err := decrypter.setTokenFetcher()

			assert.EqualValues(t, c.expectedTokenFetcher, decrypter.tokenFetcher)
			assert.True(t, c.expectError == (err != nil))
		})
	}
}

func TestKubernetesTokenFetcher(t *testing.T) {
	decrypter := &VaultDecrypter{
		vaultConfig: VaultConfig{
			Enabled:    true,
			Url:        "vault.com",
			AuthMethod: "KUBERNETES",
			Role:       "my-role",
			Path:       "my-path",
		},
	}
	err := decrypter.setTokenFetcher()
	assert.Nil(t, err)

	actualTokenFetcher, ok := decrypter.tokenFetcher.(KubernetesServiceAccountTokenFetcher)
	assert.True(t, ok)
	assert.Equal(t, "my-role", actualTokenFetcher.role)
	assert.Equal(t, "my-path", actualTokenFetcher.path)
}

func TestSetToken(t *testing.T) {
	cases := map[string]struct {
		config        VaultConfig
		expectedToken string
		expectError   bool
	}{
		"happy path": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "TOKEN",
			},
			expectedToken: "mock-token",
			expectError:   false,
		},
		"error fetching token": {
			config: VaultConfig{
				Enabled:    true,
				Url:        "vault.com",
				AuthMethod: "TOKEN",
			},
			expectedToken: "",
			expectError:   true,
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			os.Setenv("VAULT_TOKEN", c.expectedToken)
			decrypter := &VaultDecrypter{
				vaultConfig: c.config,
			}
			err := decrypter.setTokenFetcher()
			assert.Nil(t, err)

			assert.Equal(t, "", decrypter.vaultConfig.Token)

			err = decrypter.setToken()
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.expectedToken, decrypter.vaultConfig.Token)
			os.Unsetenv("VAULT_TOKEN")
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
			err := v.parseSyntax(c.params)
			assert.Equal(t, c.shouldError, err != nil)
			assert.EqualValues(t, c.expectedDecrypter, v)
		})
	}
}

func TestFetchSecret(t *testing.T) {
	cases := map[string]struct {
		decrypter       VaultDecrypter
		config          VaultConfig
		client          *MockVaultClient
		encryptedSyntax string
		expectedPath    string
		expectedData    map[string]interface{}
		expectError     bool
	}{
		"happy path": {
			decrypter: VaultDecrypter{
				vaultConfig: VaultConfig{
					Enabled:    true,
					Url:        "vault.com",
					AuthMethod: "TOKEN",
				},
				client: &MockVaultClient{
					//token: "my-token",
					readData: map[string]interface{}{},
					//readWarnings: []string{},
				},
			},
			expectedPath: "auth/path/login/user",
			expectedData: map[string]interface{}{"password": "password"},
			expectError:  false,
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			c.client.On("Write", c.expectedPath, c.expectedData).Return(c.client.writeResponse, c.client.writeErr)

			d := &VaultDecrypter{
				vaultConfig: c.config,
			}
			d.setTokenFetcher()
			token, err := d.tokenFetcher.fetchToken(c.client)
			assert.Equal(t, c.expectError, err != nil)
			assert.Equal(t, c.client.token, token)

			// assert Write() method called with expected arguments
			c.client.AssertExpectations(t)
		})
	}
}
func createTestVault(t *testing.T) (net.Listener, *api.Client) {
	t.Helper()

	// Create an in-memory, unsealed core (the "backend", if you will).
	core, keyShares, rootToken := vault.TestCoreUnsealed(t)
	_ = keyShares

	// Start an HTTP server for the core.
	ln, addr := http.TestServer(t, core)

	// Create a client that talks to the server, initially authenticating with
	// the root token.
	conf := api.DefaultConfig()
	conf.Address = addr

	client, err := api.NewClient(conf)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(rootToken)

	// Setup required secrets, policies, etc.
	_, err = client.Logical().Write("secret/foo", map[string]interface{}{
		"secret": "bar",
	})
	if err != nil {
		t.Fatal(err)
	}

	return ln, client
}
