package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"configbridge/internal/insights"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// Converser is the one Bedrock Runtime call we use (an interface so tests can
// stand in for AWS).
type Converser interface {
	Converse(context.Context, *bedrockruntime.ConverseInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

// NewBedrock drafts with a Bedrock model via the Converse API. Credentials
// come from the AWS default chain (env, shared config, ECS/EC2 role); no key
// is ever passed through ConfigBridge itself.
func NewBedrock(rt Converser, model string) *Client {
	return &Client{Bedrock: rt, Model: model}
}

// bedrockOnce makes one Converse call. Structured output = a forced call to a
// single tool whose input schema is the schema, so the reply is the tool
// input, already parsed as JSON by Bedrock.
func (c *Client) bedrockOnce(ctx context.Context, msgs []message, s schema) (string, insights.Usage, time.Duration, error) {
	none := insights.Usage{}
	toolName := "submit_" + s.name
	in := &bedrockruntime.ConverseInput{
		ModelId:         aws.String(c.Model),
		InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(12000)},
		ToolConfig: &types.ToolConfiguration{
			Tools: []types.Tool{&types.ToolMemberToolSpec{Value: types.ToolSpecification{
				Name:        aws.String(toolName),
				Description: aws.String(s.desc),
				InputSchema: &types.ToolInputSchemaMemberJson{Value: document.NewLazyDocument(s.body)},
			}}},
			ToolChoice: &types.ToolChoiceMemberTool{Value: types.SpecificToolChoice{Name: aws.String(toolName)}},
		},
	}
	for _, m := range msgs {
		text := &types.ContentBlockMemberText{Value: m.Content}
		switch m.Role {
		case "system":
			in.System = append(in.System, &types.SystemContentBlockMemberText{Value: m.Content})
		case "assistant":
			in.Messages = append(in.Messages, types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{text}})
		default:
			in.Messages = append(in.Messages, types.Message{Role: types.ConversationRoleUser, Content: []types.ContentBlock{text}})
		}
	}
	out, e := c.Bedrock.Converse(ctx, in)
	if e != nil {
		return "", none, bedrockWait(e), bedrockErr(e)
	}
	u := none
	if t := out.Usage; t != nil && t.InputTokens != nil && t.OutputTokens != nil {
		u = insights.Usage{Known: true, Input: int64(*t.InputTokens), Output: int64(*t.OutputTokens), Total: int64(*t.InputTokens) + int64(*t.OutputTokens)}
	}
	if out.StopReason == types.StopReasonMaxTokens {
		return "", u, 0, fmt.Errorf("%w: model output too long", ErrUpstream)
	}
	msg, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return "", u, 0, fmt.Errorf("%w: unexpected response", ErrUpstream)
	}
	for _, b := range msg.Value.Content {
		tu, ok := b.(*types.ContentBlockMemberToolUse)
		if !ok || aws.ToString(tu.Value.Name) != toolName || tu.Value.Input == nil {
			continue
		}
		// smithy documents decode by `document` tags, not `json`: take the raw JSON
		b, e := tu.Value.Input.MarshalSmithyDocument()
		if e != nil || !json.Valid(b) {
			return "", u, time.Second, fmt.Errorf("%w: output not in schema", ErrUpstream)
		}
		return string(b), u, 0, nil
	}
	return "", u, time.Second, fmt.Errorf("%w: model did not submit an answer", ErrUpstream)
}

// bedrockWait: throttling is retried after a pause (the SDK has already
// retried with backoff); everything else is final.
func bedrockWait(e error) time.Duration {
	var th *types.ThrottlingException
	var busy *types.ServiceUnavailableException
	if errors.As(e, &th) || errors.As(e, &busy) {
		return 10 * time.Second
	}
	return 0
}

// bedrockErr names the failure without echoing AWS messages (they can carry
// ARNs and account ids).
func bedrockErr(e error) error {
	var denied *types.AccessDeniedException
	var notFound *types.ResourceNotFoundException
	var invalid *types.ValidationException
	var th *types.ThrottlingException
	switch {
	case errors.As(e, &denied):
		return fmt.Errorf("%w: Bedrock access denied (IAM permission or model access)", ErrUpstream)
	case errors.As(e, &notFound):
		return fmt.Errorf("%w: Bedrock model not found in this region", ErrUpstream)
	case errors.As(e, &th):
		return fmt.Errorf("%w: provider rate limit, try again in a minute", ErrUpstream)
	case errors.As(e, &invalid):
		return fmt.Errorf("%w: Bedrock rejected the request", ErrUpstream)
	case strings.Contains(e.Error(), "no EC2 IMDS role found"), strings.Contains(e.Error(), "failed to retrieve credentials"):
		return fmt.Errorf("%w: no AWS credentials", ErrUpstream)
	}
	return fmt.Errorf("%w: Bedrock unavailable", ErrUpstream)
}
