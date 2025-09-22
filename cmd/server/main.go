package main

import (
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"

	"github.com/yourorg/authz/pkg/cache"
	"github.com/yourorg/authz/pkg/config"
	"github.com/yourorg/authz/pkg/service"
	"github.com/yourorg/authz/pkg/zitadel"
	"github.com/yourorg/authz/internal/middleware"
)

func main() {
	_ = godotenv.Load()
	cfg := config.LoadConfig()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis ping failed: %v", err)
	}

	cacheImpl := cache.NewRedisCache(rdb, cfg.CacheTTL)
	zitadelClient := zitadel.NewHTTPClient(cfg.ZitadelBaseURL, cfg.ZitadelToken, cfg)
	svc := service.New(zitadelClient, cacheImpl, cfg.CacheTTL)

	r := gin.Default()
	api := r.Group("/v1")

	api.POST("/roles/batch", func(c *gin.Context) {
		var req []zitadel.RoleInput
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid"})
			return
		}
		_, err := svc.CreateRoles(c.Request.Context(), req)
		if err != nil {
			c.JSON(500, gin.H{"error": "create_failed", "detail": err.Error()})
			return
		}
		
		c.JSON(201, gin.H{"ok": true})
	})

	api.POST("/roles/assign/batch", func(c *gin.Context) {
		var req struct {
			UserID  string   `json:"user_id" binding:"required"`
			RoleIDs []string `json:"role_ids" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid"})
			return
		}
		if err := svc.AssignRolesToUser(c.Request.Context(), req.UserID, req.RoleIDs); err != nil {
			c.JSON(500, gin.H{"error": "assign_failed", "detail": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})

	api.DELETE("/roles/:role", func(c *gin.Context) {
		role := c.Param("role")
		if role == "" {
			c.JSON(400, gin.H{"error": "missing role"})
			return
		}
		if err := svc.DeleteRole(c.Request.Context(), role); err != nil {
			c.JSON(500, gin.H{"error": "delete_failed", "detail": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})

	api.DELETE("/roles/:role/users/:user", func(c *gin.Context) {
		role := c.Param("role")
		user := c.Param("user")
		if role == "" || user == "" {
			c.JSON(400, gin.H{"error": "missing params"})
			return
		}
		if err := svc.RemoveRoleFromUser(c.Request.Context(), role, user); err != nil {
			c.JSON(500, gin.H{"error": "remove_failed", "detail": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})

	api.POST("/roles", func(c *gin.Context) {
		var req struct {
			Name string `json:"name" binding:"required"`
			Desc string `json:"desc"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid", "detail": err.Error()})
			return
		}
		id, err := svc.CreateRole(c.Request.Context(), req.Name, req.Desc)
		if err != nil {
			c.JSON(500, gin.H{"error": "create_failed", "detail": err.Error()})
			return
		}
		c.JSON(201, gin.H{"role_id": id})
	})

	api.POST("/roles/assign", func(c *gin.Context) {
		var req struct {
			RoleID string `json:"role_id" binding:"required"`
			UserID string `json:"user_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid"})
			return
		}
		if err := svc.AssignRole(c.Request.Context(), req.RoleID, req.UserID); err != nil {
			c.JSON(500, gin.H{"error": "assign_failed", "detail": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})

	api.POST("/webhook/zitadel", func(c *gin.Context) {
		var evt struct {
			UserID string `json:"user_id"`
			Type   string `json:"type"`
			Role   string `json:"role,omitempty"`
		}
		if err := c.ShouldBindJSON(&evt); err != nil {
			c.JSON(400, gin.H{"error": "invalid"})
			return
		}
		if evt.UserID != "" {
			_ = svc.InvalidateRoles(c.Request.Context(), evt.UserID)
		}
		if evt.Type == "role.deleted" && evt.Role != "" {
			_, _ = svc.StartRemoveRoleCleanup(c.Request.Context(), evt.Role)
		}
		c.Status(200)
	})

	api.POST("/roles/remove/async", func(c *gin.Context) {
		var req struct{ Role string `json:"role" binding:"required"` }
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid"})
			return
		}
		jobID, err := svc.StartRemoveRoleCleanup(c.Request.Context(), req.Role)
		if err != nil {
			c.JSON(500, gin.H{"error": "start_failed", "detail": err.Error()})
			return
		}
		c.JSON(202, gin.H{"job_id": jobID})
	})

	api.GET("/jobs/:id", func(c *gin.Context) {
		jobID := c.Param("id")
		if jobID == "" {
			c.JSON(400, gin.H{"error": "missing job id"})
			return
		}
		status, err := svc.GetCleanupJobStatus(c.Request.Context(), jobID)
		if err != nil {
			c.JSON(404, gin.H{"error": "not_found", "detail": err.Error()})
			return
		}
		c.JSON(200, status)
	})

	r.GET("/v1/me/profile", middleware.RoleMiddleware(svc), func(c *gin.Context) {
		rolesI, _ := c.Get(middleware.ContextRolesKey)
		c.JSON(200, gin.H{"user": c.GetHeader("X-User-ID"), "roles": rolesI})
	})

	log.Printf("starting on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}