package proxy

import (
	"testing"

	"github.com/codex2api/database"
)

// TestUpstreamModelMismatch 三态语义：未观测 nil、一致 false、不一致 true；
// 大小写不敏感等值判一致。
func TestUpstreamModelMismatch(t *testing.T) {
	if got := upstreamModelMismatch("gpt-5", ""); got != nil {
		t.Errorf("未观测应为 nil, got %v", *got)
	}
	if got := upstreamModelMismatch("gpt-5", "  "); got != nil {
		t.Errorf("空白观测应为 nil, got %v", *got)
	}
	got := upstreamModelMismatch("gpt-5.3-codex", "GPT-5.3-Codex")
	if got == nil || *got {
		t.Errorf("大小写差异应判一致(false), got %v", got)
	}
	got = upstreamModelMismatch("gpt-5.3-codex", "gpt-5.6-luna")
	if got == nil || !*got {
		t.Errorf("模型不同应判不一致(true), got %v", got)
	}
}

// TestUpstreamTraceSnapshotApplyModel 观测值应随 trace 落入用量日志，
// mismatch 与 EffectiveModel 比对。
func TestUpstreamTraceSnapshotApplyModel(t *testing.T) {
	snap := upstreamTraceSnapshot{accountID: 7, UpstreamModel: "gpt-5.6-luna"}
	input := &database.UsageLogInput{AccountID: 7, EffectiveModel: "gpt-5.3-codex"}
	snap.apply(input)
	if input.UpstreamResponseModel != "gpt-5.6-luna" {
		t.Errorf("UpstreamResponseModel = %q", input.UpstreamResponseModel)
	}
	if input.UpstreamModelMismatch == nil || !*input.UpstreamModelMismatch {
		t.Errorf("应标记不一致, got %v", input.UpstreamModelMismatch)
	}

	// 账号不匹配（failover 换号后的旧快照）不应用。
	input2 := &database.UsageLogInput{AccountID: 8, EffectiveModel: "gpt-5.3-codex"}
	snap.apply(input2)
	if input2.UpstreamResponseModel != "" || input2.UpstreamModelMismatch != nil {
		t.Error("异账号快照不应写入模型观测")
	}
}

// TestCodexUpstreamModelFromFrame WS metadata 帧的 headers 里应能取到模型。
func TestCodexUpstreamModelFromFrame(t *testing.T) {
	frame := []byte(`{"type":"response.metadata","headers":{"openai-model":"gpt-5.6-luna","x-codex-turn-state":"abc"}}`)
	if got := codexUpstreamModelFromFrame(frame); got != "gpt-5.6-luna" {
		t.Errorf("model = %q, want gpt-5.6-luna", got)
	}
	// 不相关的帧零开销返回空。
	if got := codexUpstreamModelFromFrame([]byte(`{"type":"response.completed"}`)); got != "" {
		t.Errorf("无模型帧应返回空, got %q", got)
	}
}
