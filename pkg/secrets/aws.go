package secrets

import (
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/jackc/pgx/v5"
)

type AWSClient interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

// KMSClient creates a tenant's own key on its first secret write. Optional:
// without it, tenants need an operator-assigned kms_key_id.
type KMSClient interface {
	CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	EnableKeyRotation(context.Context, *kms.EnableKeyRotationInput, ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error)
	ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
}
type AWS struct {
	Client AWSClient
	KMS    KMSClient
	Store  *store.Store
	Prefix string
}

// tenantKey returns the tenant's KMS key, creating one on first use. Lazy (not
// at sign-up) so accounts that never store a credential cost nothing. Keys are
// tagged app=configbridge (the IAM policy only allows creating/using keys with
// that tag) and rotate yearly. Losing a bind race schedules our key's deletion.
func (a *AWS) tenantKey(ctx context.Context, tenant string) (string, error) {
	scope := a.Store.ForTenant(tenant)
	var key string
	if e := scope.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT kms_key_id FROM tenants WHERE tenant_id=$1", tenant).Scan(&key)
	}); e != nil {
		return "", ErrUnavailable
	}
	if key != "" || a.KMS == nil {
		return key, nil
	}
	out, e := a.KMS.CreateKey(ctx, &kms.CreateKeyInput{
		Description: aws.String("configbridge tenant " + tenant + " credentials"),
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("app"), TagValue: aws.String("configbridge")},
			{TagKey: aws.String("tenant"), TagValue: aws.String(tenant)},
		},
	})
	if e != nil || out == nil || out.KeyMetadata == nil || out.KeyMetadata.Arn == nil {
		return "", ErrUnavailable
	}
	created := *out.KeyMetadata.Arn
	if _, e = a.KMS.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{KeyId: aws.String(created)}); e != nil {
		a.discardKey(ctx, created)
		return "", ErrUnavailable
	}
	e = scope.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT bind_tenant_kms_key($1)", created).Scan(&key)
	})
	if e != nil || key != created {
		a.discardKey(ctx, created)
	}
	if e != nil || key == "" {
		return "", ErrUnavailable
	}
	return key, nil
}
func (a *AWS) discardKey(ctx context.Context, id string) {
	_, _ = a.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(id), PendingWindowInDays: aws.Int32(7)})
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
	key, e := a.tenantKey(ctx, tenant)
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
