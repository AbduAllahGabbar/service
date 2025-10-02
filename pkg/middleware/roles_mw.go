package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AbduAllahGabbar/service/pkg/service"
	"github.com/gin-gonic/gin"
)

const ContextRolesKey = "user_roles"
const ContextUserIDKey = "user_id"


func RoleMiddleware(svc *service.Service) gin.HandlerFunc {
	zitadelDomain := strings.TrimRight(os.Getenv("ZITADEL_DOMAIN"), "/")
	if zitadelDomain == "" {
		log.Println("warning: ZITADEL_DOMAIN is not set (RoleMiddleware will fail for opaque tokens)")
	}

	return func(c *gin.Context) {
		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))

		if userID == "" {
			auth := strings.TrimSpace(c.GetHeader("Authorization"))
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				log.Println("RoleMiddleware: missing Authorization bearer or X-User-ID")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user id or bearer token"})
				return
			}

			tokenStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			sub, err := fetchUserSub(c.Request.Context(), zitadelDomain, tokenStr)
			if err != nil || sub == "" {
				log.Printf("RoleMiddleware: failed to resolve user from token: %v\n", err)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "detail": err.Error()})
				return
			}
			userID = sub
			log.Printf("RoleMiddleware: resolved user id %s from token\n", userID)
		}

		roles, err := svc.GetUserRoles(c.Request.Context(), userID)
		if err != nil {
			log.Printf("RoleMiddleware: GetUserRoles failed for %s: %v\n", userID, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles", "detail": err.Error()})
			return
		}

		c.Set(ContextUserIDKey, userID)
		c.Set(ContextRolesKey, roles)
		c.Next()
	}
}

func fetchUserSub(parentCtx context.Context, zitadelDomain, token string) (string, error) {
	if strings.TrimSpace(zitadelDomain) == "" {
		return "", fmt.Errorf("zitadel domain not configured (ZITADEL_DOMAIN)")
	}
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", zitadelDomain+"/oidc/v1/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		var body any
		_ = json.NewDecoder(res.Body).Decode(&body)
		return "", fmt.Errorf("userinfo returned %d: %v", res.StatusCode, body)
	}

	var info map[string]any
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode userinfo: %w", err)
	}
	sub, _ := info["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("sub not present in userinfo response")
	}
	return sub, nil
}

func HasAnyRole(userRoles []string, rolesToCheck ...string) bool {
	roleSet := make(map[string]struct{}, len(userRoles))
	for _, r := range userRoles {
		roleSet[r] = struct{}{}
	}

	for _, check := range rolesToCheck {
		if _, ok := roleSet[check]; ok {
			return true
		}
	}
	return false
}