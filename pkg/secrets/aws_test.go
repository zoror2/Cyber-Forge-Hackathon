package secrets

import (
	"configbridge/internal/testutil"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"sync"
	"testing"
)

type fakeAWS struct {
	mu     sync.Mutex
	values map[string]string
	keys   map[string]string
}

func (f *fakeAWS) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[*in.SecretId]
	if !ok {
		return nil, &types.ResourceNotFoundException{}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}
func (f *fakeAWS) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.values[*in.Name]; ok {
		return nil, &types.ResourceExistsException{}
	}
	f.values[*in.Name] = *in.SecretString
	f.keys[*in.Name] = *in.KmsKeyId
	return &secretsmanager.CreateSecretOutput{}, nil
}
func (f *fakeAWS) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[*in.SecretId] = *in.SecretString
	return &secretsmanager.PutSecretValueOutput{}, nil
}
func TestAWSNamespaceKMSRotationAndBinding(t *testing.T) {
	db := testutil.Setup(t)
	f := &fakeAWS{values: map[string]string{}, keys: map[string]string{}}
	backend := &AWS{Client: f, Store: db.Store, Prefix: "configbridge/"}
	ctx := context.Background()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if e := backend.Write(ctx, tenant, "same", tenant, "api.example.com"); e != nil {
			t.Fatal(e)
		}
		if f.keys["configbridge/"+tenant+"/same"] != "kms-"+tenant {
			t.Fatal("wrong tenant KMS key")
		}
		value, _, e := backend.Read(ctx, tenant, "same")
		if e != nil || value != tenant {
			t.Fatal("wrong tenant secret")
		}
	}
	if e := backend.Write(ctx, "tenant-a", "same", "rotated", "api.example.com"); e != nil {
		t.Fatal(e)
	}
	if e := backend.Write(ctx, "tenant-a", "same", "bad", "other.example.com"); e == nil {
		t.Fatal("binding changed")
	}
	value, _, e := backend.Read(ctx, "tenant-b", "same")
	if e != nil || value != "tenant-b" {
		t.Fatal("rotation affected other tenant")
	}
	raw, _ := json.Marshal(envelope{"wrong", "api.example.com", "tenant-a"})
	f.values["configbridge/tenant-b/same"] = string(raw)
	if _, _, e = backend.Read(ctx, "tenant-b", "same"); e == nil {
		t.Fatal("foreign envelope accepted")
	}
}
