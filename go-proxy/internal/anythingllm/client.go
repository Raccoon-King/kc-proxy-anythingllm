package anythingllm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client handles admin calls to AnythingLLM API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// User represents a minimal AnythingLLM user.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// AuthTokenResponse wraps the simple SSO token response.
type AuthTokenResponse struct {
	Token     string `json:"token"`
	LoginPath string `json:"loginPath"`
}

func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 10 * time.Second},
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

	return c.http.Do(req)
}

func decodeJSON[T any](r io.Reader, dst *T) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
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
		return "", fmt.Errorf("user %s not found and auto-create disabled", email)
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
		return u.ID, nil
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

	for _, pattern := range queries {
		path := fmt.Sprintf(pattern, url.QueryEscape(email))
		resp, err := c.do(ctx, http.MethodGet, path, nil)
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
				return u.ID, nil
			}
		}
	}

	return "", fmt.Errorf("user not found in AnythingLLM for %s", email)
}

// IssueAuthToken requests a Simple SSO token for a user ID.
func (c *Client) IssueAuthToken(ctx context.Context, userID string) (*AuthTokenResponse, error) {
	if userID == "" {
		return nil, errors.New("empty userID")
	}
	path := fmt.Sprintf("/api/v1/users/%s/issue-auth-token", url.PathEscape(userID))
	resp, err := c.do(ctx, http.MethodGet, path, nil)
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
