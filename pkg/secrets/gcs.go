package secrets

import (
	"cloud.google.com/go/storage"
	"fmt"
	"golang.org/x/net/context"
	"io/ioutil"
)

type GcsSecret struct {
	bucket   string
	filepath string
	key      string
}

type GcsDecrypter struct {
	params map[string]string
	ctx    context.Context
}

func NewGcsDecrypter(params map[string]string) *GcsDecrypter {
	return &GcsDecrypter{params: params, ctx: context.Background()}
}

func (gcs *GcsDecrypter) Decrypt() (string, error) {
	gcsSecret, err := ParseGcsSecret(gcs.params)
	if err != nil {
		return "", err
	}
	return gcsSecret.fetchSecret(gcs.ctx)
}

func ParseGcsSecret(params map[string]string) (GcsSecret, error) {
	var gcsSecret GcsSecret

	bucket, ok := params["b"]
	if !ok {
		return GcsSecret{}, fmt.Errorf("secret format error - 'b' for bucket is required")
	}
	gcsSecret.bucket = bucket

	filepath, ok := params["f"]
	if !ok {
		return GcsSecret{}, fmt.Errorf("secret format error - 'f' for file is required")
	}
	gcsSecret.filepath = filepath

	key, ok := params["k"]
	if ok {
		gcsSecret.key = key
	}

	return gcsSecret, nil
}

func (secret *GcsSecret) fetchSecret(ctx context.Context) (string, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to create GCS client: %s", err.Error())
	}
	bucket := client.Bucket(secret.bucket)
	r, err := bucket.Object(secret.filepath).NewReader(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to get reader for bucket: %s, file: %s, error: %v", secret.bucket, secret.filepath, err)
	}
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("unable to download file from bucket: %s, file: %s, error: %v", secret.bucket, secret.filepath, err)
	}

	if len(secret.key) > 0 {
		return parseSecretFile(b, secret.key)
	}

	return string(b), nil
}
