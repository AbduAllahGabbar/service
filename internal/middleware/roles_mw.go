package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AbduAllahGabbar/service/pkg/service"
	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const ContextRolesKey = "user_roles"
const ContextUserIDKey = "user_id"

var (
	jwks     *keyfunc.JWKS
	jwksOnce sync.Once
	jwksErr  error

	zitadelDomain string
)

func ensureJWKS() {
	jwksOnce.Do(func() {
		d := strings.TrimRight(os.Getenv("ZITADEL_DOMAIN"), "/")
		if d == "" {
			jwksErr = fmt.Errorf("ZITADEL_DOMAIN not set")
			return
		}
		zitadelDomain = d
		jwksURL := d + "/.well-known/jwks.json"
		opts := keyfunc.Options{
			RefreshInterval: time.Hour,
		}
		k, err := keyfunc.Get(jwksURL, opts)
		if err != nil {
			jwksErr = fmt.Errorf("failed to get jwks from %s: %w", jwksURL, err)
			return
		}
		jwks = k
		log.Printf("initialized JWKS from %s", jwksURL)
	})
}

func getUserID(tokenStr string) (string, error) {
	if jwks != nil {
		token, err := jwt.Parse(tokenStr, jwks.Keyfunc)
		if err == nil && token != nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if sub, ok := claims["sub"].(string); ok && sub != "" {
					return sub, nil
				}
			}
		}
	}

	if zitadelDomain == "" {
		return "", fmt.Errorf("jwks not initialised and zitadel domain unknown")
	}

	req, _ := http.NewRequest("GET", zitadelDomain+"/oidc/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var b map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&b)
		return "", fmt.Errorf("userinfo request returned %d (%v)", resp.StatusCode, b)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("failed to decode userinfo response: %w", err)
	}
	if sub, ok := data["sub"].(string); ok && sub != "" {
		return sub, nil
	}
	return "", fmt.Errorf("sub not found in userinfo")
}
func RoleMiddleware(svc *service.Service) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := strings.TrimSpace(c.GetHeader("X-User-ID"))

        if userID == "" {
            auth := c.GetHeader("Authorization")
            if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
                log.Println("❌ Missing Authorization header or not Bearer")
                c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user id or bearer token"})
                return
            }

            tokenStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
            log.Println("🔑 Incoming token:", tokenStr)

            var err error
            userID, err = getUserID(tokenStr)
            if err != nil || userID == "" {
                log.Printf("❌ Invalidssss token, err=%v, userID=%s\n", err, userID)
                c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalidsssss token", "detail": err.Error()})
                return
            }

            log.Println("✅ Extracted userID:", userID)
        }

        roles, err := svc.GetUserRoles(c.Request.Context(), userID)
        if err != nil {
            log.Printf("❌ Failed to fetch roles for user %s: %v", userID, err)
            c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles", "detail": err.Error()})
            return
        }

        log.Printf("✅ User %s roles: %v", userID, roles)

        c.Set(ContextUserIDKey, userID)
        c.Set(ContextRolesKey, roles)
        c.Next()
    }
}


// func RoleMiddleware(svc *service.Service) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))

// 		if userID == "" {
// 			auth := c.GetHeader("Authorization")
// 			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
// 				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user id or bearer token"})
// 				return
// 			}
// 			tokenStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
// 			log.Println("Incoming token:", tokenStr)
// 			var err error

// 			userID, err = getUserID(tokenStr)
// 			if err != nil || userID == "" {
// 				 log.Printf("Token parse failed: %v", err) 
// 				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "detail": err.Error()})
// 				return
// 			}
// 		}

// 		roles, err := svc.GetUserRoles(c.Request.Context(), userID)
// 		if err != nil {
// 			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles", "detail": err.Error()})
// 			return
// 		}

// 		c.Set(ContextUserIDKey, userID)
// 		c.Set(ContextRolesKey, roles)
// 		c.Next()
// 	}
// }
