package secrets

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type AwsSecretsManagerClient interface {
	FetchSecret(region string, secretName string) (*secretsmanager.GetSecretValueOutput, error)
}

type AwsSecretsManagerClientImpl struct{}

func NewAwsSecretsManagerClient() AwsSecretsManagerClient {
	return &AwsSecretsManagerClientImpl{}
}

func (a *AwsSecretsManagerClientImpl) FetchSecret(region string, secretName string) (*secretsmanager.GetSecretValueOutput, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}

	sm := secretsmanager.New(sess)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	result, err := sm.GetSecretValue(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			code := aerr.Code()
			return nil, fmt.Errorf("failed to fetch secret from AWS SM, Code: %v, Err: %v", code, aerr.Error())
		} else {
			return nil, fmt.Errorf("failed to fetch secret from AWS SM, Err: %v", err.Error())
		}
	}

	return result, nil
}
