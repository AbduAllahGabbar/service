package middleware

import (
	"net/http"

	"github.com/AbduAllahGabbar/service/pkg/service"
	"github.com/gin-gonic/gin"
)

const ContextRolesKey = "user_roles"

func RoleMiddleware(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user id"})
			return
		}
		roles, err := svc.GetUserRoles(c.Request.Context(), userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles"})
			return
		}
		c.Set(ContextRolesKey, roles)
		c.Next()
	}
}
