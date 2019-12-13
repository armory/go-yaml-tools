module github.com/armory/go-yaml-tools

go 1.13

require (
	cloud.google.com/go/storage v1.1.1
	// Upgrade once this bug is fixed: https://github.com/aws/aws-sdk-go/issues/2972 (slow decrypting of S3 secrets)
	github.com/aws/aws-sdk-go v1.25.37
	github.com/frankban/quicktest v1.4.1 // indirect
	github.com/golang/groupcache v0.0.0-20191002201903-404acd9df4cc // indirect
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.2 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20190909201928-35325e2c3262
	github.com/imdario/mergo v0.3.5
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/pierrec/lz4 v2.3.0+incompatible // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.1.1
	github.com/stretchr/testify v1.3.0
	go.opencensus.io v0.22.1 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4 // indirect
	golang.org/x/exp v0.0.0-20191002040644-a1355ae1e2c3 // indirect
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de // indirect
	golang.org/x/net v0.0.0-20191007182048-72f939374954 // indirect
	golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // indirect
	golang.org/x/time v0.0.0-20190921001708-c4c64cad1fd0 // indirect
	golang.org/x/tools v0.0.0-20191007185444-6536af71d98a // indirect
	google.golang.org/api v0.11.0 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20191007204434-a023cd5227bd // indirect
	google.golang.org/grpc v1.24.0 // indirect
	gopkg.in/yaml.v2 v2.2.2
)
