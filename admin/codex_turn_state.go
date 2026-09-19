package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// RefreshCodexTurnState 手动触发某账号的 turn-state 探测刷新（经专用代理换出口
// IP 拿非降智 token）。请求体可带表单当前值 {proxy, models}——手动刷新不看
// 自动刷新开关（点击本身就是授权），也支持用未保存的表单值直接探测，避免
// "先保存才能刷"的操作陷阱。
func (h *Handler) RefreshCodexTurnState(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account id"})
		return
	}
	account := h.store.FindByID(id)
	if account == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}
	if h.authCacheProxy == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "proxy handler 未就绪"})
		return
	}
	var body struct {
		Proxy  string `json:"proxy"`
		Models string `json:"models"`
	}
	// 空体是合法的老调用方式（用已保存配置）。
	if c.Request.Body != nil {
		_ = json.NewDecoder(c.Request.Body).Decode(&body)
	}
	if err := validateOptionalProxyURL(body.Proxy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "proxy 无效: " + err.Error()})
		return
	}
	result, err := h.authCacheProxy.RefreshCodexTurnStateManual(c.Request.Context(), account, body.Proxy, body.Models)
	if err != nil {
		// 探测失败也返回结构化结果（长度/错误），运维要看的就是它。
		c.JSON(http.StatusConflict, result)
		return
	}
	c.JSON(http.StatusOK, result)
}

// StopCodexTurnStateRefine 停止某账号的 turn-state 死磕刷新循环。死磕开关本身
// （codex_turn_state_refine_enabled）不受影响——它仍是开着的，重启或再次保存
// 会重新起循环；要彻底关掉请走账号 PATCH。这里只负责"现在就停"。
func (h *Handler) StopCodexTurnStateRefine(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account id"})
		return
	}
	if h.store.FindByID(id) == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	}
	if h.authCacheProxy == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "proxy handler 未就绪"})
		return
	}
	stopped := h.authCacheProxy.StopCodexTurnStateRefine(id)
	c.JSON(http.StatusOK, gin.H{"stopped": stopped, "refining": h.authCacheProxy.CodexTurnStateRefining(id)})
}

// codexTurnStateRefining 透传 proxy 侧死磕循环的运行状态（响应构建用）。
func (h *Handler) codexTurnStateRefining(accountID int64) bool {
	if h.authCacheProxy == nil {
		return false
	}
	return h.authCacheProxy.CodexTurnStateRefining(accountID)
}
