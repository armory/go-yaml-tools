package secrets

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"testing"
)

type MockAwsSecretsManagerClient struct {
	mock.Mock
	payload string
}

func (m *MockAwsSecretsManagerClient) FetchSecret(region string, secretName string) (*secretsmanager.GetSecretValueOutput, error) {
	mockPayloadBytes, _ := ioutil.ReadFile("../../test/aws-secrets-manager/" + m.payload)
	res := &secretsmanager.GetSecretValueOutput{}
	err := json.Unmarshal(mockPayloadBytes, res)
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
	m.On("fetchSecret", mock.Anything).Return(res, nil)
	return res, nil
}

func TestNewAwsSecretsManagerDecrypter(t *testing.T) {
	cases := []struct {
		name          string
		params        string
		expectedError string
		isFile        bool
	}{
		{
			"The provided params has less than the 2 required tokens",
			"r:some-region",
			GenericMalformedKeyError,
			false,
		},
		{
			"The provided params has a malformed kv pair",
			"r:some-region!s!some-secret",
			GenericMalformedKeyError,
			false,
		},
		{
			"The provided params is missing required param region",
			"g:some-region!s:some-secret",
			RegionMissingError,
			false,
		},
		{
			"The provided params is missing required param secret name",
			"r:some-region!g:some-secret",
			SecretNameMissingError,
			false,
		},
		{
			"An encrypted file specified a key param",
			"r:some-region!s:some-secret!k:some-key",
			EncryptedFilesShouldNotSpecifyKeyError,
			true,
		},
		{
			"extra unknown params where included",
			"r:some-region!s:some-secret!k:some-key!q:some-unknown-thing",
			GenericMalformedKeyError,
			false,
		},
		{
			"the happy path returns no error for file",
			"r:some-region!s:some-secret",
			"",
			true,
		},
		{
			"the happy path returns no error for plain text secret",
			"r:some-region!s:some-secret",
			"",
			false,
		},
		{
			"the happy path returns no error for kv pair secret",
			"r:some-region!s:some-secret!k:some-key",
			"",
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sut, err := NewAwsSecretsManagerDecrypter(nil, c.isFile, c.params)
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			} else {
				assert.Equal(t, c.isFile, sut.IsFile())
			}
			assert.Equal(t, c.expectedError, errorMsg)
		})
	}
}

func TestDecrypt(t *testing.T) {
	cases := []struct {
		name           string
		secretKey      string
		payload        string
		expectedError  string
		isFile         bool
		expectedFile   string
		expectedSecret string
	}{
		{
			"The provided params is for a binary file, such as a .pfx PKCS cert, ca, key wrapper file",
			"some-secret",
			"binary.json",
			"",
			true,
			"example-cert-ca-key-bundle.pfx",
			"",
		},
		{
			"The provided params is for a plain text file, such as a ssh key",
			"some-secret",
			"ssh-key.json",
			"",
			true,
			"example-ssh-key.pem",
			"",
		},
		{
			"The provided params is for a kv map and a specific key",
			"foo",
			"kvpairs.json",
			"",
			false,
			"",
			"bar",
		},
		{
			"The provided params is for a single plaintext secret",
			"",
			"plaintext.json",
			"",
			false,
			"",
			"value",
		},
		{
			"The provided params is for a kv map and a specific key, but the configured secret is plain text",
			"some-secret",
			"plaintext.json",
			MalformedKVPairSecretPayload,
			false,
			"",
			"",
		},
		{
			"The provided params is for a kv map and a specific key, but the configured secret is binary",
			"some-secret",
			"binary.json",
			MalformedKVPairSecretPayload,
			false,
			"",
			"",
		},
		{
			"The provided params is for a kv map and a specific key, but the configured secrets value is an embedded object and not a string",
			"some-secret",
			"custom.json",
			MalformedKVPairSecretPayload,
			false,
			"",
			"",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			awsSecretsManagerClient := &MockAwsSecretsManagerClient{payload: c.payload}
			sut := &AwsSecretsManagerDecrypter{isFile: c.isFile, region: "some-region", secretName: "some-secret", secretKey: c.secretKey, awsSecretsManagerClient: awsSecretsManagerClient}

			secret, err := sut.Decrypt()
			var errorMsg string
			if err != nil {
				errorMsg = err.Error()
			}
			assert.Equal(t, c.expectedError, errorMsg)

			if c.expectedError != "" {
				return
			}

			if c.isFile {
				expectedBytes, _ := ioutil.ReadFile("../../test/aws-secrets-manager/" + c.expectedFile)
				actualBytes, _ := ioutil.ReadFile(secret)
				assert.Equal(t, expectedBytes, actualBytes)
			} else {
				assert.Equal(t, c.expectedSecret, secret)
			}
		})
	}
}
