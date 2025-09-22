package zitadel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/sony/gobreaker"

	"github.com/yourorg/authz/pkg/config"
)

type RoleInput struct {
	Name string `json:"name"`
	Desc string `json:"desc,omitempty"`
}

type Client interface {
	CreateRole(ctx context.Context, name, desc string) (string, error)
	CreateRoles(ctx context.Context, roles []RoleInput) ([]string, error)
	AssignRoleToUser(ctx context.Context, roleID, userID string) error
	AssignRolesToUser(ctx context.Context, userID string, roleIDs []string) error
	DeleteRole(ctx context.Context, roleID string) error
	RemoveRoleFromUser(ctx context.Context, roleID, userID string) error
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

type httpClient struct {
	base         *url.URL
	cli          *retryablehttp.Client
	token        string
	cb           *gobreaker.CircuitBreaker
	project      string
	projectGrant string
}

func NewHTTPClient(baseURL, token string, cfg *config.Config) Client {
	u, _ := url.Parse(baseURL)

	cli := retryablehttp.NewClient()
	cli.RetryMax = cfg.RetryMax
	cli.RetryWaitMin = 200 * time.Millisecond
	cli.RetryWaitMax = 1 * time.Second
	cli.HTTPClient.Timeout = cfg.RequestTimeout
	cli.Logger = nil

	settings := gobreaker.Settings{
		Name:        "ZitadelCB",
		MaxRequests: cfg.CBMaxRequests,
		Interval:    cfg.CBInterval,
		Timeout:     cfg.CBTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			if counts.ConsecutiveFailures >= 5 {
				return true
			}
			if counts.Requests >= 10 && float64(counts.TotalFailures)/float64(counts.Requests) > 0.5 {
				return true
			}
			return false
		},
	}
	cb := gobreaker.NewCircuitBreaker(settings)

	return &httpClient{
		base:         u,
		cli:          cli,
		token:        token,
		cb:           cb,
		project:      cfg.ProjectID,
		projectGrant: cfg.ProjectGrantID,
	}
}

func (h *httpClient) makeURL(p string) string {
	u := *h.base
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u.Path = path.Clean(p)
	return u.String()
}


func (h *httpClient) doRequest(req *retryablehttp.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")

	res, err := h.cb.Execute(func() (interface{}, error) {
		r, e := h.cli.Do(req)
		if e == nil && r != nil && r.StatusCode >= 500 {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			return nil, fmt.Errorf("server error: %d %s", r.StatusCode, string(body))
		}
		return r, e
	})
	if err != nil {
		return nil, err
	}
	if rr, ok := res.(*http.Response); ok {
		return rr, nil
	}
	return nil, fmt.Errorf("unexpected response type from cb")
}


func (h *httpClient) CreateRoles(ctx context.Context, roles []RoleInput) ([]string, error) {
	type bulkRole struct {
		Key         string `json:"key"`
		DisplayName string `json:"displayName"`
		Group       string `json:"group,omitempty"`
	}
	br := make([]bulkRole, 0, len(roles))
	for _, r := range roles {
		br = append(br, bulkRole{
			Key:         r.Name,
			DisplayName: r.Desc,
			Group:       "default",
		})
	}
	payload := map[string]interface{}{
		"roles": br,
	}
	b, _ := json.Marshal(payload)

	endpoint := fmt.Sprintf("/management/v1/projects/%s/roles/_bulk", h.project)
	req, _ := retryablehttp.NewRequest("POST", h.makeURL(endpoint), strings.NewReader(string(b)))
	req = req.WithContext(ctx)

	resp, err := h.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create roles bulk failed: %d %s", resp.StatusCode, string(body))
	}

	var out struct {
		Roles []struct {
			Key string `json:"key"`
		} `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err == nil && len(out.Roles) > 0 {
		keys := make([]string, 0, len(out.Roles))
		for _, r := range out.Roles {
			keys = append(keys, r.Key)
		}
		return keys, nil
	}
	// return h.ListRoles(ctx)

	return  nil, nil

	//  return nil, fmt.Errorf("create roles bulk: invalid response")
}

// func (h *httpClient) ListRoles(ctx context.Context) ([]string, error) {
// 	endpoint := fmt.Sprintf("/management/v1/projects/%s/roles", h.project)
// 	req, _ := retryablehttp.NewRequest("GET", h.makeURL(endpoint), nil)
// 	req = req.WithContext(ctx)

// 	resp, err := h.doRequest(req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode >= 300 {
// 		body, _ := io.ReadAll(resp.Body)
// 		return nil, fmt.Errorf("list roles failed: %d %s", resp.StatusCode, string(body))
// 	}

// 	var out struct {
// 		Result []struct {
// 			Key string `json:"key"`
// 		} `json:"result"`
// 	}
// 	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
// 		return nil, err
// 	}

// 	keys := make([]string, 0, len(out.Result))
// 	for _, r := range out.Result {
// 		keys = append(keys, r.Key)
// 	}
// 	return keys, nil
// }


func (h *httpClient) CreateRole(ctx context.Context, name, desc string) (string, error) {
	keys, err := h.CreateRoles(ctx, []RoleInput{{Name: name, Desc: desc}})
	if err != nil {
		return "", err
	}
	if len(keys) > 0 {
		return keys[0], nil
	}
	return "", nil
}

func (h *httpClient) AssignRoleToUser(ctx context.Context, roleID, userID string) error {
	payload := map[string]interface{}{
		"projectId":      h.project,
		"projectGrantId": h.projectGrant,
		"roleKeys":       []string{roleID},
	}
	b, _ := json.Marshal(payload)

	endpoint := fmt.Sprintf("/management/v1/users/%s/grants", userID)
	req, _ := retryablehttp.NewRequest("POST", h.makeURL(endpoint), strings.NewReader(string(b)))
	req = req.WithContext(ctx)

	resp, err := h.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("assign role failed: %d %s", resp.StatusCode, string(body))
	}
	return nil
}

func (h *httpClient) AssignRolesToUser(ctx context.Context, userID string, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return nil
	}
	payload := map[string]interface{}{
		"projectId":      h.project,
		"projectGrantId": h.projectGrant,
		"roleKeys":       roleIDs,
	}
	b, _ := json.Marshal(payload)

	endpoint := fmt.Sprintf("/management/v1/users/%s/grants", userID)
	req, _ := retryablehttp.NewRequest("POST", h.makeURL(endpoint), strings.NewReader(string(b)))
	req = req.WithContext(ctx)

	resp, err := h.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("assign roles failed: %d %s", resp.StatusCode, string(body))
	}
	return nil
}

func (h *httpClient) DeleteRole(ctx context.Context, roleID string) error {
	endpoint := fmt.Sprintf("/management/v1/projects/%s/roles/%s", h.project, roleID)
	req, _ := retryablehttp.NewRequest("DELETE", h.makeURL(endpoint), nil)
	req = req.WithContext(ctx)

	resp, err := h.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete role failed: %d %s", resp.StatusCode, string(body))
	}
	return nil
}

func (h *httpClient) RemoveRoleFromUser(ctx context.Context, roleID, userID string) error {
	// Step 1: ابحث عن الـ grants بتاعة اليوزر
	searchPayload := map[string]interface{}{
		"queries": []interface{}{
			map[string]interface{}{
				"user_id_query": map[string]string{
					"user_id": userID,
				},
			},
		},
	}
	b, _ := json.Marshal(searchPayload)
	searchEndpoint := "/management/v1/users/grants/_search"
	req, _ := retryablehttp.NewRequest("POST", h.makeURL(searchEndpoint), strings.NewReader(string(b)))
	req = req.WithContext(ctx)

	resp, err := h.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("search grants failed: %d %s", resp.StatusCode, string(body))
	}

	// Step 2: عدل struct roleKeys تبقى array
	var out struct {
		Result []struct {
			GrantId  string   `json:"grantId"`
			ID       string   `json:"id"`
			RoleKeys []string `json:"roleKeys"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("failed to decode grants search: %w", err)
	}

	// Step 3: دور على grant اللي فيه الـ roleID المطلوب
	var grantToDelete string
	for _, r := range out.Result {
		for _, role := range r.RoleKeys {
			if role == roleID {
				if r.GrantId != "" {
					grantToDelete = r.GrantId
				} else {
					grantToDelete = r.ID
				}
				break
			}
		}
	}

	if grantToDelete == "" {
		return fmt.Errorf("grant for user %s and role %s not found", userID, roleID)
	}

	// Step 4: امسح الـ grant
	delEndpoint := fmt.Sprintf("/management/v1/users/%s/grants/%s", userID, grantToDelete)
	delReq, _ := retryablehttp.NewRequest("DELETE", h.makeURL(delEndpoint), nil)
	delReq = delReq.WithContext(ctx)
	delResp, err := h.doRequest(delReq)
	if err != nil {
		return err
	}
	defer delResp.Body.Close()
	if delResp.StatusCode >= 300 {
		body, _ := io.ReadAll(delResp.Body)
		return fmt.Errorf("delete grant failed: %d %s", delResp.StatusCode, string(body))
	}
	return nil
}

func (h *httpClient) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	payload := map[string]interface{}{
		"queries": []interface{}{
			map[string]interface{}{
				"user_id_query": map[string]string{
					"user_id": userID,
				},
			},
		},
	}
	b, _ := json.Marshal(payload)

	endpoint := "/management/v1/users/grants/_search"
	req, _ := retryablehttp.NewRequest("POST", h.makeURL(endpoint), strings.NewReader(string(b)))
	req = req.WithContext(ctx)

	resp, err := h.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get user roles failed: %d %s", resp.StatusCode, string(body))
	}

	var out struct {
		Result []struct {
			RoleKeys []string `json:"roleKeys"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode roles failed: %w", err)
	}

	roles := make([]string, 0)
	for _, r := range out.Result {
		roles = append(roles, r.RoleKeys...)
	}

	return roles, nil
}

