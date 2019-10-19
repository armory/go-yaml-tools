package secrets

import "testing"

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
