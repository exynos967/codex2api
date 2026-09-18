package admin

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// RefreshCodexTurnState 手动触发某账号的 turn-state 探测刷新（经专用代理换出口
// IP 拿非降智 token）。周期巡检与降智观测触发之外的第三个入口，方便运维在
// 换代理节点后立即验证。
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
	result, err := h.authCacheProxy.RefreshCodexTurnState(c.Request.Context(), account)
	if err != nil {
		// 探测失败也返回结构化结果（长度/错误），运维要看的就是它。
		c.JSON(http.StatusConflict, result)
		return
	}
	c.JSON(http.StatusOK, result)
}
