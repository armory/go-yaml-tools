package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptedKey(t *testing.T) {
	cases := []struct {
		name        string
		password    string
		errExpected bool
		expected    string
	}{
		{
			name:        "not encrypted",
			password:    "asdf1234",
			errExpected: false,
			expected:    "asdf1234",
		},
		{
			name:        "encrypted noop",
			password:    "encrypted:noop!asdf1234",
			errExpected: false,
			expected:    "asdf1234",
		},
		{
			name:        "encrypted fail",
			password:    "encrypted:doesnotexist!asdf1234",
			errExpected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Server{
				config: &ServerConfig{
					Ssl: Ssl{
						KeyPassword: c.password,
					},
				},
			}
			p, err := s.getKeyPassword()
			if assert.Equal(t, c.errExpected, err != nil) {
				assert.Equal(t, c.expected, p)
			}
		})
	}
}
