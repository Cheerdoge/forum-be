package middleware

import (
	"forum-gateway/handler"
	"forum/pkg/errno"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// WebhookGuard 限制 webhook 回调只能被审核服务调用
func WebhookGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := viper.GetString("audit.audit_api_key")
		if apiKey != "" && c.GetHeader("api_key") == apiKey {
			c.Next()
			return
		}

		handler.SendError(c, errno.ErrPermissionDenied, nil, "api_key 校验不符", handler.GetLine())
		c.Abort()
	}
}
