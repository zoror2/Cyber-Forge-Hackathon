package secrets

import (
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/jackc/pgx/v5"
)

type AWSClient interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}
type AWS struct {
	Client AWSClient
	Store  *store.Store
	Prefix string
}

func (a *AWS) path(tenant, name string) (string, error) {
	if !config.ValidID(tenant) || !config.ValidID(name) {
		return "", ErrUnavailable
	}
	return a.Prefix + tenant + "/" + name, nil
}
func (a *AWS) Read(ctx context.Context, tenant, name string) (string, string, error) {
	path, e := a.path(tenant, name)
	if e != nil {
		return "", "", e
	}
	out, e := a.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(path)})
	if e != nil || out == nil || out.SecretString == nil {
		return "", "", ErrUnavailable
	}
	var env envelope
	if json.Unmarshal([]byte(*out.SecretString), &env) != nil || env.Tenant != tenant {
		return "", "", ErrUnavailable
	}
	return env.Value, env.Host, nil
}
func (a *AWS) Write(ctx context.Context, tenant, name, value, host string) error {
	path, e := a.path(tenant, name)
	if e != nil {
		return e
	}
	var key string
	e = a.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT kms_key_id FROM tenants WHERE tenant_id=$1", tenant).Scan(&key)
	})
	if e != nil || key == "" {
		return ErrUnavailable
	}
	raw, e := json.Marshal(envelope{value, host, tenant})
	if e != nil {
		return ErrUnavailable
	}
	_, e = a.Client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(path), KmsKeyId: aws.String(key), SecretString: aws.String(string(raw))})
	var exists *types.ResourceExistsException
	if errors.As(e, &exists) {
		_, bound, readErr := a.Read(ctx, tenant, name)
		if readErr != nil || bound != host {
			return ErrBinding
		}
		_, e = a.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(path), SecretString: aws.String(string(raw))})
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
