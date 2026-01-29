package anythingllm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var ErrUserNotFound = errors.New("anythingllm user not found")

// Client handles admin calls to AnythingLLM API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	retries int
	backoff time.Duration
}

// User represents a minimal AnythingLLM user.
type User struct {
	ID       json.Number `json:"id"`
	Email    string      `json:"email"`
	Username string      `json:"username"`
	Name     string      `json:"name"`
	Role     string      `json:"role"`
}

// AuthTokenResponse wraps the simple SSO token response.
type AuthTokenResponse struct {
	Token     string `json:"token"`
	LoginPath string `json:"loginPath"`
}

func New(baseURL, apiKey string) *Client {
	return NewWithHTTPClient(baseURL, apiKey, &http.Client{Timeout: 10 * time.Second}, 0, 200*time.Millisecond)
}

// NewWithHTTPClient allows callers to supply a tuned HTTP client and retry behavior.
func NewWithHTTPClient(baseURL, apiKey string, httpClient *http.Client, retryMax int, retryBackoff time.Duration) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if retryMax < 0 {
		retryMax = 0
	}
	if retryBackoff <= 0 {
		retryBackoff = 200 * time.Millisecond
	}
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  apiKey,
		http:    httpClient,
		retries: retryMax,
		backoff: retryBackoff,
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if os.Getenv("DEBUG_HTTP") == "true" {
		log.Printf("[DBG] http %s %s auth=%s", method, path, req.Header.Get("Authorization"))
	}

	return c.http.Do(req)
}

func (c *Client) doWithRetry(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var lastErr error
	backoff := c.backoff
	for attempt := 0; attempt <= c.retries; attempt++ {
		resp, err := c.do(ctx, method, path, body)
		if err == nil {
			if resp.StatusCode < 500 {
				return resp, nil
			}
			lastErr = fmt.Errorf("server error: %s", resp.Status)
			_ = resp.Body.Close()
		} else {
			lastErr = err
		}
		if attempt >= c.retries {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			backoff = backoff * 2
		}
	}
	return nil, lastErr
}

func decodeJSON[T any](r io.Reader, dst *T) error {
	dec := json.NewDecoder(r)
	return dec.Decode(dst)
}

// EnsureUser fetches a user by email, creating if allowed.
func (c *Client) EnsureUser(ctx context.Context, email, name, role string, allowCreate bool) (string, error) {
	if email == "" {
		return "", errors.New("missing email in token claims")
	}

	if userID, _ := c.findUserID(ctx, email); userID != "" {
		return userID, nil
	}

	if !allowCreate {
		return "", ErrUserNotFound
	}

	payload := map[string]string{
		"email": email,
		"name":  name,
	}
	if role != "" {
		payload["role"] = role
	}

	resp, err := c.do(ctx, http.MethodPost, "/api/v1/users", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var u User
		if err := decodeJSON(resp.Body, &u); err != nil {
			return "", err
		}
		if strings.TrimSpace(u.ID.String()) == "" {
			return "", errors.New("create user failed: empty id in response")
		}
		return u.ID.String(), nil
	}

	if resp.StatusCode == http.StatusConflict {
		if userID, err := c.findUserID(ctx, email); err == nil && userID != "" {
			return userID, nil
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return "", fmt.Errorf("create user failed: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
}

// findUserID tries to locate a user by email using a best-effort API surface.
func (c *Client) findUserID(ctx context.Context, email string) (string, error) {
	queries := []string{
		"/api/v1/users?email=%s",
		"/api/v1/users?search=%s",
	}
	target := strings.ToLower(email)
	targetLocal := target
	if at := strings.Index(target, "@"); at != -1 {
		targetLocal = target[:at]
	}

	for _, pattern := range queries {
		path := fmt.Sprintf(pattern, url.QueryEscape(email))
		resp, err := c.doWithRetry(ctx, http.MethodGet, path, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			continue
		}

		var payload struct {
			Users []User `json:"users"`
			Data  []User `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			continue
		}
		candidates := append(payload.Users, payload.Data...)
		for _, u := range candidates {
			if strings.EqualFold(u.Email, email) {
				return u.ID.String(), nil
			}
			if strings.EqualFold(u.Username, email) || strings.EqualFold(strings.ToLower(u.Username), targetLocal) {
				return u.ID.String(), nil
			}
		}
	}

	return "", ErrUserNotFound
}

// IssueAuthToken requests a Simple SSO token for a user ID.
func (c *Client) IssueAuthToken(ctx context.Context, userID string) (*AuthTokenResponse, error) {
	if userID == "" {
		return nil, errors.New("empty userID")
	}
	path := fmt.Sprintf("/api/v1/users/%s/issue-auth-token", url.PathEscape(userID))
	resp, err := c.doWithRetry(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issue auth token failed: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}

	var tokenResp AuthTokenResponse
	if err := decodeJSON(resp.Body, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}
