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

// RoleMiddleware: يعتمد X-User-ID إن موجود، وإلا يستخدم Authorization Bearer token.
// لو التوكن opaque (Zitadel access token) ينادي /oidc/v1/userinfo لاستخراج sub.
// يخزن user_id و user_roles في gin.Context.
func RoleMiddleware(svc *service.Service) gin.HandlerFunc {
	// read zitadel domain from env once
	zitadelDomain := strings.TrimRight(os.Getenv("ZITADEL_DOMAIN"), "/")
	if zitadelDomain == "" {
		// warning only; requests will fail with clear error later
		log.Println("warning: ZITADEL_DOMAIN is not set (RoleMiddleware will fail for opaque tokens)")
	}

	return func(c *gin.Context) {
		// 1) prefer X-User-ID (convenience for internal calls/tests)
		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))

		// 2) otherwise use Authorization: Bearer <token>
		if userID == "" {
			auth := strings.TrimSpace(c.GetHeader("Authorization"))
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				log.Println("RoleMiddleware: missing Authorization bearer or X-User-ID")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user id or bearer token"})
				return
			}

			tokenStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			// call userinfo to resolve sub (works with opaque access tokens)
			sub, err := fetchUserSub(c.Request.Context(), zitadelDomain, tokenStr)
			if err != nil || sub == "" {
				log.Printf("RoleMiddleware: failed to resolve user from token: %v\n", err)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "detail": err.Error()})
				return
			}
			userID = sub
			log.Printf("RoleMiddleware: resolved user id %s from token\n", userID)
		}

		// 3) load roles via service (use request context to propagate cancel/timeouts)
		roles, err := svc.GetUserRoles(c.Request.Context(), userID)
		if err != nil {
			log.Printf("RoleMiddleware: GetUserRoles failed for %s: %v\n", userID, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles", "detail": err.Error()})
			return
		}

		// 4) store in context for handlers
		c.Set(ContextUserIDKey, userID)
		c.Set(ContextRolesKey, roles)
		c.Next()
	}
}

// fetchUserSub calls /oidc/v1/userinfo with a timeout and returns the "sub" field.
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
