package service

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/singleflight"

	"github.com/yourorg/authz/pkg/cache"
	"github.com/yourorg/authz/pkg/zitadel"
)

type Service struct {
	zitadel zitadel.Client
	cache   cache.Cache
	group   singleflight.Group
	ttl     time.Duration
}

func New(z zitadel.Client, c cache.Cache, ttl time.Duration) *Service {
	return &Service{zitadel: z, cache: c, ttl: ttl}
}

func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	if roles, ok, err := s.cache.GetRoles(ctx, userID); err == nil && ok {
		return roles, nil
	} else if err != nil {
	}

	v, err, _ := s.group.Do("roles:"+userID, func() (interface{}, error) {
		var roles []string
		op := func() error {
			r, e := s.zitadel.GetUserRoles(ctx, userID)
			if e != nil {
				return e
			}
			roles = r
			return nil
		}
		ebo := backoff.NewExponentialBackOff()
		ebo.MaxElapsedTime = 10 * time.Second

		b := backoff.WithContext(ebo, ctx)

		if err := backoff.Retry(op, b); err != nil {
			return nil, err
		}

		_ = s.cache.SetRoles(ctx, userID, roles, s.ttl)
		return roles, nil
	})
	if err != nil {
		return nil, err
	}
	roles, ok := v.([]string)
	if !ok {
		return nil, errors.New("unexpected type")
	}
	return roles, nil
}

func (s *Service) CreateRole(ctx context.Context, name, desc string) (string, error) {
	return s.zitadel.CreateRole(ctx, name, desc)
}

func (s *Service) CreateRoles(ctx context.Context, roles []zitadel.RoleInput) ([]string, error) {
	return s.zitadel.CreateRoles(ctx, roles)
}

func (s *Service) AssignRole(ctx context.Context, roleID, userID string) error {
	if err := s.zitadel.AssignRoleToUser(ctx, roleID, userID); err != nil {
		return err
	}
	return s.cache.InvalidateRoles(ctx, userID)
}

func (s *Service) AssignRolesToUser(ctx context.Context, userID string, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return nil
	}
	if err := s.zitadel.AssignRolesToUser(ctx, userID, roleIDs); err != nil {
		return err
	}
	return s.cache.InvalidateRoles(ctx, userID)
}

func (s *Service) DeleteRole(ctx context.Context, roleID string) error {
	if err := s.zitadel.DeleteRole(ctx, roleID); err != nil {
		return err
	}
	_, err := s.cache.StartRemoveRoleJob(ctx, roleID)
	return err
}

func (s *Service) RemoveRoleFromUser(ctx context.Context, roleID, userID string) error {
	if err := s.zitadel.RemoveRoleFromUser(ctx, roleID, userID); err != nil {
		return err
	}
	return s.cache.InvalidateRoles(ctx, userID)
}

func (s *Service) InvalidateRoles(ctx context.Context, userID string) error {
	return s.cache.InvalidateRoles(ctx, userID)
}

func (s *Service) StartRemoveRoleCleanup(ctx context.Context, role string) (string, error) {
	return s.cache.StartRemoveRoleJob(ctx, role)
}

func (s *Service) GetCleanupJobStatus(ctx context.Context, jobID string) (*cache.CleanupJobStatus, error) {
	return s.cache.GetJobStatus(ctx, jobID)
}
