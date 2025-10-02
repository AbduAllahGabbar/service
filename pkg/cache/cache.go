package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Cache interface {
	GetRoles(ctx context.Context, userID string) ([]string, bool, error)
	SetRoles(ctx context.Context, userID string, roles []string, ttl time.Duration) error
	InvalidateRoles(ctx context.Context, userID string) error
	RemoveRoleFromAllCaches(ctx context.Context, role string) (int, error)
	StartRemoveRoleJob(ctx context.Context, role string) (string, error)
	GetJobStatus(ctx context.Context, jobID string) (*CleanupJobStatus, error)
}

type rolesValue struct {
	Roles     []string  `json:"roles"`
	FetchedAt time.Time `json:"fetched_at"`
	Version   string    `json:"version,omitempty"`
}

type CleanupJobStatus struct {
	JobID     string    `json:"job_id"`
	Role      string    `json:"role"`
	Processed int       `json:"processed"`
	Updated   int       `json:"updated"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type redisCache struct {
	rdb        *redis.Client
	defaultTTL time.Duration
}

func NewRedisCache(rdb *redis.Client, defaultTTL time.Duration) Cache {
	return &redisCache{rdb: rdb, defaultTTL: defaultTTL}
}

func (c *redisCache) key(userID string) string {
	return fmt.Sprintf("roles:%s", userID)
}

func (c *redisCache) GetRoles(ctx context.Context, userID string) ([]string, bool, error) {
	b, err := c.rdb.Get(ctx, c.key(userID)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var v rolesValue
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, false, err
	}
	return v.Roles, true, nil
}

func (c *redisCache) SetRoles(ctx context.Context, userID string, roles []string, ttl time.Duration) error {
	v := rolesValue{Roles: roles, FetchedAt: time.Now(), Version: "v1"}
	b, _ := json.Marshal(v)
	if ttl == 0 {
		ttl = c.defaultTTL
	}
	return c.rdb.Set(ctx, c.key(userID), b, ttl).Err()
}

func (c *redisCache) InvalidateRoles(ctx context.Context, userID string) error {
	return c.rdb.Del(ctx, c.key(userID)).Err()
}

func (c *redisCache) RemoveRoleFromAllCaches(ctx context.Context, role string) (int, error) {
	var cursor uint64
	updated := 0
	batchSize := int64(100)
	for {
		keys, cur, err := c.rdb.Scan(ctx, cursor, "roles:*", batchSize).Result()
		if err != nil {
			return updated, err
		}
		cursor = cur

		if len(keys) == 0 {
			if cursor == 0 {
				break
			}
			continue
		}

		vals, err := c.rdb.MGet(ctx, keys...).Result()
		if err != nil {
			return updated, err
		}

		pipe := c.rdb.Pipeline()
		for i, raw := range vals {
			if raw == nil {
				continue
			}
			b, ok := raw.(string)
			if !ok {
				continue
			}
			var v rolesValue
			if err := json.Unmarshal([]byte(b), &v); err != nil {
				continue
			}
			newRoles := v.Roles[:0]
			removed := false
			for _, r := range v.Roles {
				if r == role {
					removed = true
					continue
				}
				newRoles = append(newRoles, r)
			}
			if !removed {
				continue
			}
			v.Roles = newRoles
			nb, _ := json.Marshal(v)

			ttl, err := c.rdb.TTL(ctx, keys[i]).Result()
			var expiration time.Duration
			if err == nil {
				if ttl < 0 {
					// ttl == -1 => no expiration; keep no expiry
					expiration = 0
				} else {
					expiration = ttl
				}
			} else {
				expiration = c.defaultTTL
			}
			if expiration > 0 {
				pipe.Set(ctx, keys[i], nb, expiration)
			} else {
				pipe.Set(ctx, keys[i], nb, 0)
			}
			updated++
		}
		if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
			return updated, err
		}

		if cursor == 0 {
			break
		}
	}
	return updated, nil
}

func (c *redisCache) StartRemoveRoleJob(ctx context.Context, role string) (string, error) {
	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	status := CleanupJobStatus{JobID: jobID, Role: role, Processed: 0, Updated: 0, Status: "running", StartedAt: time.Now()}
	b, _ := json.Marshal(status)
	if err := c.rdb.Set(ctx, "job:roles_cleanup:"+jobID, b, 24*time.Hour).Err(); err != nil {
		return "", err
	}
	go func(j string, r string) {
		_ = c.runRemoveRoleJob(context.Background(), j, r)
	}(jobID, role)
	return jobID, nil
}

func (c *redisCache) runRemoveRoleJob(ctx context.Context, jobID, role string) error {
	key := "job:roles_cleanup:" + jobID
	update := func(s CleanupJobStatus) error {
		b, _ := json.Marshal(s)
		return c.rdb.Set(ctx, key, b, 24*time.Hour).Err()
	}
	status := CleanupJobStatus{JobID: jobID, Role: role, Processed: 0, Updated: 0, Status: "running", StartedAt: time.Now()}
	_ = update(status)
	var cursor uint64
	batchSize := int64(100)
	for {
		keys, cur, err := c.rdb.Scan(ctx, cursor, "roles:*", batchSize).Result()
		if err != nil {
			status.Status = "failed"
			status.Error = err.Error()
			status.FinishedAt = time.Now()
			_ = update(status)
			return err
		}
		cursor = cur
		if len(keys) == 0 && cursor == 0 {
			break
		}

		vals, err := c.rdb.MGet(ctx, keys...).Result()
		if err != nil {
			status.Status = "failed"
			status.Error = err.Error()
			status.FinishedAt = time.Now()
			_ = update(status)
			return err
		}

		pipe := c.rdb.Pipeline()
		for i, raw := range vals {
			status.Processed++
			if raw == nil {
				if status.Processed%50 == 0 {
					_ = update(status)
				}
				continue
			}
			b, ok := raw.(string)
			if !ok {
				continue
			}
			var v rolesValue
			if err := json.Unmarshal([]byte(b), &v); err != nil {
				continue
			}
			
			newRoles := v.Roles[:0]
			removed := false
			for _, r := range v.Roles {
				if r == role {
					removed = true
					continue
				}
				newRoles = append(newRoles, r)
			}
			if removed {
				v.Roles = newRoles
				nb, _ := json.Marshal(v)
				ttl, err := c.rdb.TTL(ctx, keys[i]).Result()
				var setTTL time.Duration
				if err == nil {
					if ttl < 0 {
						setTTL = 0
					} else {
						setTTL = ttl
					}
				} else {
					setTTL = c.defaultTTL
				}
				if setTTL > 0 {
					pipe.Set(ctx, keys[i], nb, setTTL)
				} else {
					pipe.Set(ctx, keys[i], nb, 0)
				}
				status.Updated++
			}
			if status.Processed%50 == 0 {
				_ = update(status)
			}
		}
		if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
			status.Status = "failed"
			status.Error = err.Error()
			status.FinishedAt = time.Now()
			_ = update(status)
			return err
		}
		_ = update(status)
		if cursor == 0 {
			break
		}
	}
	status.Status = "done"
	status.FinishedAt = time.Now()
	_ = update(status)
	return nil
}

func (c *redisCache) GetJobStatus(ctx context.Context, jobID string) (*CleanupJobStatus, error) {
	b, err := c.rdb.Get(ctx, "job:roles_cleanup:"+jobID).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("job not found")
	}
	if err != nil {
		return nil, err
	}
	var s CleanupJobStatus
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}