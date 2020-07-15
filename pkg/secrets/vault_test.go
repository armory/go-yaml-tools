package secrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateVaultConfig(t *testing.T) {
	type args struct {
		vaultConfig VaultConfig
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "if Token, we don't need to look in env var",
			args: args{
				vaultConfig: VaultConfig{
					Enabled:    true,
					Url:        "vault.com",
					AuthMethod: "TOKEN",
					Role:       "",
					Path:       "",
					Token:      "s.123123123",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateVaultConfig(tt.args.vaultConfig); (err != nil) != tt.wantErr {
				t.Errorf("validateVaultConfig() error = %v, wantErr %v", err, tt.wantErr)
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

func TestClientGetsNamespace(t *testing.T) {
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
	}

	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {
			d := VaultDecrypter{
				vaultConfig: c.cfg,
			}

			client, err := d.FetchVaultClient(c.cfg.Token)
			assert.Nil(t, err)
			assert.Equal(t, c.cfg.Token, client.Token())

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

