package secrets

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	yamlParse "gopkg.in/yaml.v2"
	"reflect"
	"strings"
)

const (
	MAX_API_RETRY = 10
)

type S3Secret struct {
	region   string
	bucket   string
	filepath string
	key      string
}

type S3Decrypter struct {
	secretConfig string
}

func NewS3Decrypter(secretConfig string) *S3Decrypter {
	return &S3Decrypter{secretConfig}
}

func (s3 *S3Decrypter) Decrypt() (string, error) {
	s3Secret, err := parseS3SecretConfig(s3.secretConfig)
	if err != nil {
		return "", err
	}
	secret, err := s3Secret.fetchSecret()
	if err != nil {
		return "", err
	}

	return secret, nil
}

func parseS3SecretConfig(secretConfig string) (S3Secret, error) {
	var s3Secret S3Secret
	configs := strings.Split(secretConfig, "!")
	if len(configs) < 2 {
		return S3Secret{}, fmt.Errorf("bad format for secret syntax: %q", secretConfig)
	}
	for _, element := range configs {
		kv := strings.Split(element, ":")
		if len(kv) < 2 {
			return S3Secret{}, fmt.Errorf("bad format for key-value pair in secret syntax %q: %s",
				secretConfig, element)
		}
		switch kv[0] {
		case "encrypted":
			// do nothing
		case "r":
			s3Secret.region = kv[1]
		case "b":
			s3Secret.bucket = kv[1]
		case "f":
			s3Secret.filepath = kv[1]
		case "k":
			s3Secret.key = kv[1]
		default:
			return S3Secret{}, fmt.Errorf("invalid key in secret syntax %q: %s", secretConfig, kv[0])
		}
	}
	return s3Secret, nil
}

func (secret *S3Secret) fetchSecret() (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:     aws.String(secret.region),
		MaxRetries: aws.Int(MAX_API_RETRY),
	})
	if err != nil {
		return "", err
	}

	downloader := s3manager.NewDownloader(sess)

	contents := aws.NewWriteAtBuffer([]byte{})
	size, err := downloader.Download(contents,
		&s3.GetObjectInput{
			Bucket: aws.String(secret.bucket),
			Key:    aws.String(secret.filepath),
		})
	if err != nil {
		return "", fmt.Errorf("unable to download item %q: %v", secret.filepath, err)
	}
	if size == 0 {
		return "", fmt.Errorf("file %q empty", secret.filepath)
	}

	if len(secret.key) > 0 {
		bytes := contents.Bytes()
		return parseSecretFile(bytes, secret.key)
	}

	return string(contents.Bytes()), nil
}

func parseSecretFile(fileContents []byte, key string) (string, error) {
	m := make(map[interface{}]interface{})
	if err := yamlParse.Unmarshal(fileContents, &m); err != nil {
		return "", err
	}

	for _, yamlKey := range strings.Split(key, ".") {
		switch s := m[yamlKey].(type) {
		case map[interface{}]interface{}:
			m = s
		case string:
			return s, nil
		case nil:
			return "", fmt.Errorf("error parsing secret file: couldn't find key %q in yaml", key)
		default:
			return "", fmt.Errorf("error parsing secret file: unknown type %q with value %q",
				reflect.TypeOf(s), s)
		}
	}

	return "", fmt.Errorf("error parsing secret file for key %q", key)
}
