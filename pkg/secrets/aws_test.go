package secrets

import (
	"configbridge/internal/testutil"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
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

type fakeKMS struct {
	mu       sync.Mutex
	created  []string
	deleted  []string
	rotation []string
}

func (f *fakeKMS) CreateKey(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(in.Tags) != 2 || *in.Tags[0].TagValue != "configbridge" {
		return nil, errors.New("missing app tag")
	}
	arn := fmt.Sprintf("arn:aws:kms:test:1:key/%d-%s", len(f.created), *in.Tags[1].TagValue)
	f.created = append(f.created, arn)
	return &kms.CreateKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Arn: aws.String(arn)}}, nil
}
func (f *fakeKMS) EnableKeyRotation(_ context.Context, in *kms.EnableKeyRotationInput, _ ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotation = append(f.rotation, *in.KeyId)
	return &kms.EnableKeyRotationOutput{}, nil
}
func (f *fakeKMS) ScheduleKeyDeletion(_ context.Context, in *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, *in.KeyId)
	return &kms.ScheduleKeyDeletionOutput{}, nil
}

// A self-signed-up tenant (empty kms_key_id) gets its own rotating key on the
// first write; concurrent first writes bind exactly one key and discard the
// rest; tenants with an operator-assigned key keep it.
func TestAWSCreatesTenantKMSKeyOnFirstWrite(t *testing.T) {
	db := testutil.Setup(t)
	ctx := context.Background()
	if _, e := db.Store.CreateAccount(ctx, "signup-co", "", "Owner", "o@example.com", "hash"); e != nil {
		t.Fatal(e)
	}
	f := &fakeAWS{values: map[string]string{}, keys: map[string]string{}}
	k := &fakeKMS{}
	backend := &AWS{Client: f, KMS: k, Store: db.Store, Prefix: "configbridge/"}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = backend.Write(ctx, "signup-co", fmt.Sprintf("s%d", i), "v", "api.example.com")
		}(i)
	}
	wg.Wait()
	bound := map[string]bool{}
	for i := 0; i < 4; i++ {
		bound[f.keys[fmt.Sprintf("configbridge/signup-co/s%d", i)]] = true
	}
	if len(bound) != 1 || bound[""] {
		t.Fatalf("want every secret under one tenant key, got %v", bound)
	}
	if len(k.created)-len(k.deleted) != 1 || len(k.rotation) != len(k.created) {
		t.Fatalf("created %d, discarded %d, rotated %d", len(k.created), len(k.deleted), len(k.rotation))
	}
	if e := backend.Write(ctx, "tenant-a", "x", "v", "api.example.com"); e != nil || f.keys["configbridge/tenant-a/x"] != "kms-tenant-a" {
		t.Fatal("operator-assigned key replaced")
	}
}
