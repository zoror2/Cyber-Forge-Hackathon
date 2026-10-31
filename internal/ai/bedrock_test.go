package ai

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

type fakeRT struct {
	calls int
	in    *bedrockruntime.ConverseInput
	reply func(int) (*bedrockruntime.ConverseOutput, error)
}

func (f *fakeRT) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.calls++
	f.in = in
	return f.reply(f.calls)
}

func toolReply(v map[string]any) *bedrockruntime.ConverseOutput {
	return &bedrockruntime.ConverseOutput{StopReason: types.StopReasonToolUse, Output: &types.ConverseOutputMemberMessage{Value: types.Message{
		Role: types.ConversationRoleAssistant,
		Content: []types.ContentBlock{&types.ContentBlockMemberToolUse{Value: types.ToolUseBlock{
			Name: aws.String("submit_connector_draft"), ToolUseId: aws.String("t1"), Input: document.NewLazyDocument(v)}}},
	}}}
}

func TestBedrockDraftUsesForcedToolAndValidates(t *testing.T) {
	cfg, err := os.ReadFile("../../configs/github_members.json")
	if err != nil {
		t.Fatal(err)
	}
	rt := &fakeRT{reply: func(int) (*bedrockruntime.ConverseOutput, error) {
		return toolReply(map[string]any{"config_json": string(cfg), "notes": []string{"n"}, "needed": []string{"token"},
			"optional": []string{}, "sources": []string{"https://docs.github.com", "javascript:alert(1)"}, "also_available": []string{"authentication", "bogus"}}), nil
	}}
	c := NewBedrock(rt, "test-model")
	if !c.Allowed("tenant-a") || c.Provider() != "bedrock" {
		t.Fatal("bedrock client not configured")
	}
	d, err := c.generate(context.Background(), Request{Product: "FixtureVendor", Data: "auto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rt.calls != 1 || len(d.Sources) != 1 || len(d.AlsoAvailable) != 1 {
		t.Fatalf("calls=%d sources=%v also=%v", rt.calls, d.Sources, d.AlsoAvailable)
	}
	tc, ok := rt.in.ToolConfig.ToolChoice.(*types.ToolChoiceMemberTool)
	if !ok || aws.ToString(tc.Value.Name) != "submit_connector_draft" || len(rt.in.System) != 1 || aws.ToString(rt.in.ModelId) != "test-model" {
		t.Fatal("request not shaped as a forced tool call with a system prompt")
	}
}

func TestBedrockErrorsAreNotEchoed(t *testing.T) {
	secret := "arn:aws:iam::123456789012:user/someone"
	for _, e := range []error{&types.AccessDeniedException{Message: aws.String(secret)}, &types.ValidationException{Message: aws.String(secret)}, errors.New(secret)} {
		rt := &fakeRT{reply: func(int) (*bedrockruntime.ConverseOutput, error) { return nil, e }}
		_, err := NewBedrock(rt, "m").generate(context.Background(), Request{Product: "Okta", Data: "auto"}, nil)
		if !errors.Is(err, ErrUpstream) || strings.Contains(err.Error(), "123456789012") {
			t.Fatalf("got %v", err)
		}
		if rt.calls != 1 {
			t.Fatalf("non-throttle error retried %d times", rt.calls)
		}
	}
}

func TestBedrockRetriesNoToolUse(t *testing.T) {
	cfg, _ := os.ReadFile("../../configs/github_members.json")
	rt := &fakeRT{reply: func(n int) (*bedrockruntime.ConverseOutput, error) {
		if n == 1 {
			return &bedrockruntime.ConverseOutput{Output: &types.ConverseOutputMemberMessage{Value: types.Message{
				Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "sure"}}}}}, nil
		}
		return toolReply(map[string]any{"config_json": string(cfg), "notes": []string{}, "needed": []string{}, "optional": []string{}, "sources": []string{}, "also_available": []string{}}), nil
	}}
	if _, err := NewBedrock(rt, "m").Draft(context.Background(), Request{Product: "GitHub", Data: "auto"}, nil); err != nil || rt.calls != 2 {
		t.Fatalf("err=%v calls=%d", err, rt.calls)
	}
}
