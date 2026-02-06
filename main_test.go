package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestApp() *App {
	return NewApp(NewMemoryStore(), &OpenAIClient{}, "http://localhost:4321")
}

func TestHealthEndpoint(t *testing.T) {
	app := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP response code 200, but got: %v", w.Code)
	}
}

func TestRegisterAndLoginFlow(t *testing.T) {
	app := newTestApp()

	registerPayload := `{"username":"testuser","password":"testpass","confirmPassword":"testpass"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(registerPayload))
	req.Header.Set("Content-Type", "application/json")
	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP response code 201, but got: %v", w.Code)
	}

	loginPayload := `{"username":"testuser","password":"testpass"}`
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP response code 200, but got: %v", w.Code)
	}

	var loginResp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("Failed to parse login response: %v", err)
	}
	token := loginResp["token"]
	if token == "" {
		t.Fatalf("Expected token in login response")
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP response code 200, but got: %v", w.Code)
	}
}
