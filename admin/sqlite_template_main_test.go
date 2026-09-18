package admin

import (
	"log"
	"os"
	"testing"

	"github.com/codex2api/database"
)

// TestMain 只初始化一次 SQLite schema 模板：之后每个测试建库直接复制模板、跳过迁移，
// 把 -race 下每个测试 ~1.2s 的建库开销压到毫秒级。
func TestMain(m *testing.M) {
	// 测试里的"上游"全是 httptest 的 http:// 明文服务，而 CODEX_TRANSPORT_MODE
	// 默认已改为 utls_rustls：uTLS RoundTripper 只对 https 有意义，http:// 会被
	// 强制 TLS 握手而失败。包级默认回退 standard，让各测试聚焦业务语义；需要
	// 特定传输模式的测试仍可用 t.Setenv("CODEX_TRANSPORT_MODE", ...) 自行覆盖。
	if os.Getenv("CODEX_TRANSPORT_MODE") == "" {
		_ = os.Setenv("CODEX_TRANSPORT_MODE", "standard")
	}
	cleanup, err := database.PrepareSQLiteSchemaTemplate()
	if err != nil {
		log.Printf("SQLite schema template unavailable, tests fall back to full migrations: %v", err)
		os.Exit(m.Run())
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
