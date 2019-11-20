package secrets

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseYaml(t *testing.T) {
	cases := []struct {
		key         string
		expected    string
		shouldError bool
	}{
		{
			"rootKey",
			"rootValue",
			false,
		},
		{
			"this.is.nested",
			"nestedValue",
			false,
		},
		{
			"doesnt.exist",
			"",
			true,
		},
	}
	for _, c := range cases {
		secretBytes := []byte("rootKey: rootValue\nthis:\n is:\n  nested: nestedValue")
		actual, err := parseSecretFile(secretBytes, c.key)
		didError := (err != nil)
		if actual != c.expected || didError != c.shouldError {
			t.Errorf("for parseSecretFile(%s) with error=='%t' -- wanted [%s], "+
				"but got [%s] with error=='%t", c.key, c.shouldError, c.expected, actual, didError)
		}
	}

	invalidYaml := []byte("this:\n is:invalid\n is: yaml")
	actual, err := parseSecretFile(invalidYaml, "this.is")
	if len(actual) > 0 || err == nil {
		t.Errorf("for parseSecretFile() with invalid yaml, expected error with empty return value but got "+
			"error: %q and return value: %q", err, actual)
	}
}

func TestParseS3Secret(t *testing.T) {
	cases := []struct {
		params      map[string]string
		expected    S3Secret
		shouldError bool
	}{
		{
			map[string]string{
				"encrypted": "s3",
				"r":         "region",
				"b":         "bucket",
				"f":         "file",
			},
			S3Secret{
				region:   "region",
				bucket:   "bucket",
				filepath: "file",
			},
			false,
		},
		{
			map[string]string{
				"encrypted": "s3",
				"r":         "region",
				"b":         "bucket",
				"f":         "file",
				"k":         "key",
			},
			S3Secret{
				region:   "region",
				bucket:   "bucket",
				filepath: "file",
				key:      "key",
			},
			false,
		},
		{
			map[string]string{
				"encrypted": "s3",
				"b":         "bucket",
				"f":         "file",
			},
			S3Secret{},
			true,
		},
		{
			map[string]string{
				"encrypted": "s3",
				"r":         "region",
				"f":         "file",
			},
			S3Secret{},
			true,
		},
		{
			map[string]string{
				"encrypted": "s3",
				"r":         "region",
				"b":         "bucket",
			},
			S3Secret{},
			true,
		},
	}

	for _, c := range cases {
		s3Secret, err := ParseS3Secret(c.params)
		didError := (err != nil)
		if didError != c.shouldError || s3Secret != c.expected {
			t.Errorf("for parseS3EncryptedSecret(%s) -- expected %s with error=='%t' but got %s with error=='%t'",
				c.params, c.expected, c.shouldError, s3Secret, didError)
		}
	}
}

func TestParseGcsSecret(t *testing.T) {
	cases := []struct {
		params      map[string]string
		expected    GcsSecret
		shouldError bool
	}{
		{
			map[string]string{
				"encrypted": "gcs",
				"b":         "bucket",
				"f":         "file",
			},
			GcsSecret{
				bucket:   "bucket",
				filepath: "file",
			},
			false,
		},
		{
			map[string]string{
				"encrypted": "gcs",
				"b":         "bucket",
				"f":         "file",
				"k":         "key",
			},
			GcsSecret{
				bucket:   "bucket",
				filepath: "file",
				key:      "key",
			},
			false,
		},
		{
			map[string]string{
				"encrypted": "gcs",
				"b":         "bucket",
			},
			GcsSecret{},
			true,
		},
	}

	for _, c := range cases {
		gcsSecret, err := ParseGcsSecret(c.params)
		didError := (err != nil)
		if didError != c.shouldError || gcsSecret != c.expected {
			t.Errorf("for parseGcsEncryptedSecret(%s) -- expected %s with error=='%t' but got %s with error=='%t'",
				c.params, c.expected, c.shouldError, gcsSecret, didError)
		}
	}
}

func TestDecrypter(t *testing.T) {
	cases := []struct {
		secretConfig string
		expected     interface{}
	}{
		{
			"encrypted:s3!b:bucket",
			&S3Decrypter{},
		},
		{
			"encrypted:gcs!b:bucket",
			&GcsDecrypter{},
		},
		{
			"encrypted:vault!e:engine",
			&VaultDecrypter{},
		},
		{
			"notASecret",
			&NoopDecrypter{
				value: "notASecret",
			},
		},
	}

	for _, c := range cases {
		decrypter := NewDecrypter(c.secretConfig)
		if reflect.TypeOf(decrypter) != reflect.TypeOf(c.expected) {
			t.Errorf("for parseS3EncryptedSecret(%s) -- expected type %s but got type %s",
				c.secretConfig, reflect.TypeOf(c.expected), reflect.TypeOf(decrypter))
		}
	}
}

func TestNoSecret(t *testing.T) {
	notASecret := "notASecret"
	noSecret := NewDecrypter(notASecret)
	unchanged, _ := noSecret.Decrypt()
	if unchanged != notASecret {
		t.Errorf("for NoSecret.Decrypt(%s) -- expected unchanged string %q, but got %q",
			notASecret, notASecret, unchanged)
	}
}

func TestNoVaultConfig(t *testing.T) {
	decrypter := NewDecrypter("encrypted:vault!e:secret!n:test-secret!k:foo")
	_, err := decrypter.Decrypt()
	expectedError := "configuration not found"
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Errorf("attempting to Decrypt() without vault configured, expected error with %q but got: %q", expectedError, err)
	}
}

func TestParseVaultSecret(t *testing.T) {
	cases := []struct {
		params      map[string]string
		expected    VaultSecret
		shouldError bool
	}{
		{
			map[string]string{
				"encrypted": "vault",
				"e":         "engine",
				"n":         "path",
				"k":         "key",
			},
			VaultSecret{
				engine: "engine",
				path:   "path",
				key:    "key",
			},
			false,
		},
		{
			map[string]string{
				"encrypted": "vault",
				"e":         "engine",
				"n":         "path",
				"k":         "key",
				"b":         "true",
			},
			VaultSecret{
				engine:        "engine",
				path:          "path",
				base64Encoded: "true",
				key:           "key",
			},
			false,
		},
		{
			map[string]string{
				"encrypted": "vault",
				"n":         "path",
				"k":         "key",
			},
			VaultSecret{},
			true,
		},
		{
			map[string]string{
				"encrypted": "vault",
				"e":         "engine",
				"k":         "key",
			},
			VaultSecret{},
			true,
		},
		{
			map[string]string{
				"encrypted": "vault",
				"e":         "engine",
				"n":         "path",
			},
			VaultSecret{},
			true,
		},
	}

	for _, c := range cases {
		vaultSecret, err := parseVaultSecret(c.params)
		didError := (err != nil)
		if didError != c.shouldError || vaultSecret != c.expected {
			t.Errorf("for parseS3EncryptedSecret(%s) -- expected %s with error=='%t' but got %s with error=='%t'",
				c.params, c.expected, c.shouldError, vaultSecret, didError)
		}
	}
}
