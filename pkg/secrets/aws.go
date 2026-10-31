package secrets

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type AWSClient interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}
type AWS struct {
	Client AWSClient
	Prefix string
}

func (a *AWS) GetSecret(ctx context.Context, name string) (Secret, error) {
	out, err := a.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(a.Prefix + name)})
	if err != nil || out == nil || out.SecretString == nil {
		return Secret{}, ErrUnavailable
	}
	var e envelope
	if json.Unmarshal([]byte(*out.SecretString), &e) != nil {
		return Secret{}, ErrUnavailable
	}
	return Secret{e.Value, e.Host}, nil
}
func (a *AWS) PutSecret(ctx context.Context, name string, s Secret) error {
	raw, err := json.Marshal(envelope{s.Value, s.AllowedHost})
	if err != nil {
		return ErrUnavailable
	}
	_, err = a.Client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(a.Prefix + name), SecretString: aws.String(string(raw))})
	var exists *types.ResourceExistsException
	if errors.As(err, &exists) {
		_, err = a.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(a.Prefix + name), SecretString: aws.String(string(raw))})
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
