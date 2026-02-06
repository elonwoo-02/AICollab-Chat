package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestApp() *App {
	return NewApp(NewMemoryStore(), &OpenAIClient{})
}

func TestLoginPage(t *testing.T) {
	app := newTestApp()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP response code 200, but got: %v", w.Code)
	}
}

func TestRegisterAndLoginFlow(t *testing.T) {
	app := newTestApp()

	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "testpass")
	form.Add("confirm_password", "testpass")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("Expected HTTP response code 301, but got: %v", w.Code)
	}

	loginForm := url.Values{}
	loginForm.Add("username", "testuser")
	loginForm.Add("password", "testpass")

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.router.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("Expected HTTP response code 301, but got: %v", w.Code)
	}
}
