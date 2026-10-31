package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"strings"
	"testing"
)

func TestEncryptionAndSafeFormatting(t *testing.T) {
	l, err := NewLocal(nil, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s := Secret{"SENTINEL_ONLY_FOR_TESTS", "api.example.com"}
	raw, err := l.seal("token", s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(s.Value)) {
		t.Fatal("plaintext persisted")
	}
	got, err := l.open("token", raw)
	if err != nil || got.Value != s.Value || got.AllowedHost != s.AllowedHost {
		t.Fatal("round trip failed")
	}
	if _, err = l.open("different-name", raw); err == nil {
		t.Fatal("ciphertext copied to another secret")
	}
	raw[len(raw)-1] ^= 1
	if _, err = l.open("token", raw); err == nil {
		t.Fatal("tamper accepted")
	}
	serialized, _ := json.Marshal(s)
	if strings.Contains(fmt.Sprintf("%v %+v %#v %s", s, s, s, s), s.Value) || bytes.Contains(serialized, []byte(s.Value)) {
		t.Fatal("secret formatting leak")
	}
}

type awsFake struct {
	value  string
	name   string
	exists bool
}

func (f *awsFake) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.name = *in.SecretId
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(f.value)}, nil
}
func (f *awsFake) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	if f.exists {
		return nil, &types.ResourceExistsException{}
	}
	f.exists = true
	f.name = *in.Name
	f.value = *in.SecretString
	return &secretsmanager.CreateSecretOutput{}, nil
}
func (f *awsFake) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.name = *in.SecretId
	f.value = *in.SecretString
	return &secretsmanager.PutSecretValueOutput{}, nil
}
func TestAWSCreateRotateReadContract(t *testing.T) {
	f := &awsFake{}
	a := &AWS{Client: f, Prefix: "configbridge/"}
	ctx := context.Background()
	for _, value := range []string{"first", "second"} {
		if err := a.PutSecret(ctx, "token", Secret{value, "api.example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := a.GetSecret(ctx, "token")
	if err != nil || s.Value != "second" || s.AllowedHost != "api.example.com" || f.name != "configbridge/token" {
		t.Fatal("AWS contract mismatch")
	}
}
