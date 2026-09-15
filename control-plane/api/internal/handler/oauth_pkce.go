package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type PKCEAuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	UserID        string
	TenantID      string
	ExpiresAt     time.Time
}

type PKCEOAuthHandler struct {
	Store *store.Store
	mu    sync.Mutex
	codes map[string]PKCEAuthCode
}

func NewPKCEOAuthHandler(st *store.Store) *PKCEOAuthHandler {
	return &PKCEOAuthHandler{
		Store: st,
		codes: make(map[string]PKCEAuthCode),
	}
}

// Authorize handles GET /oauth/authorize
func (h *PKCEOAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")

	if responseType != "code" || clientID == "" || redirectURI == "" || codeChallenge == "" {
		http.Error(w, "invalid_request: missing required OAuth parameters", http.StatusBadRequest)
		return
	}

	if codeChallengeMethod != "S256" {
		http.Error(w, "invalid_request: code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	// Generate authorization code
	codeBytes := make([]byte, 32)
	_, _ = rand.Read(codeBytes)
	code := hex.EncodeToString(codeBytes)

	// Validate active user session cookie
	var sess *session.SessionInfo
	cookie, err := r.Cookie("agentcontrol_session")
	if err != nil {
		cookie, err = r.Cookie("agentwall_session")
	}
	if err == nil && cookie != nil && cookie.Value != "" {
		if s, err := session.Validate(cookie.Value); err == nil && s != nil {
			sess = s
		}
	}

	if sess == nil || sess.UserID == "" {
		// User is not authenticated; redirect to Web UI login preserving the full OAuth request
		returnTo := url.QueryEscape(r.URL.RequestURI())
		loginURL := fmt.Sprintf("/login?return_to=%s", returnTo)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	userID := sess.UserID
	tenantID := sess.TenantID
	if tenantID == "" {
		tenantID = middleware.DefaultOrganizationID
	}

	h.mu.Lock()
	// Prune expired codes
	now := time.Now()
	for k, v := range h.codes {
		if v.ExpiresAt.Before(now) {
			delete(h.codes, k)
		}
	}
	h.codes[code] = PKCEAuthCode{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		UserID:        userID,
		TenantID:      tenantID,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	h.mu.Unlock()

	// Redirect back to developer workstation callback listener
	delim := "?"
	if strings.Contains(redirectURI, "?") {
		delim = "&"
	}
	target := fmt.Sprintf("%s%scode=%s&state=%s", redirectURI, delim, code, state)
	http.Redirect(w, r, target, http.StatusFound)
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	TenantID     string `json:"tenant_id"`
	UserID       string `json:"user_id"`
}

// Token handles POST /oauth/token, POST /api/v2/auth/pkce/token, POST /api/v1/auth/token
func (h *PKCEOAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest
	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON payload"}`, http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid_request","error_description":"Malformed form payload"}`, http.StatusBadRequest)
			return
		}
		req.GrantType = r.FormValue("grant_type")
		req.ClientID = r.FormValue("client_id")
		req.Code = r.FormValue("code")
		req.CodeVerifier = r.FormValue("code_verifier")
		req.RedirectURI = r.FormValue("redirect_uri")
	}

	if req.GrantType != "authorization_code" || req.Code == "" || req.CodeVerifier == "" {
		http.Error(w, `{"error":"invalid_grant","error_description":"grant_type must be authorization_code with code and code_verifier"}`, http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	authCode, exists := h.codes[req.Code]
	if exists {
		delete(h.codes, req.Code) // One-time use
	}
	h.mu.Unlock()

	if !exists || authCode.ExpiresAt.Before(time.Now()) {
		http.Error(w, `{"error":"invalid_grant","error_description":"Authorization code is invalid or has expired"}`, http.StatusBadRequest)
		return
	}

	// Validate PKCE S256 challenge: BASE64URL_NOPAD(SHA256(code_verifier)) == code_challenge
	hasher := sha256.New()
	hasher.Write([]byte(req.CodeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	if computedChallenge != authCode.CodeChallenge {
		http.Error(w, `{"error":"invalid_grant","error_description":"PKCE code_verifier challenge verification failed"}`, http.StatusBadRequest)
		return
	}

	// Generate secure tokens
	accBytes := make([]byte, 32)
	refBytes := make([]byte, 32)
	_, _ = rand.Read(accBytes)
	_, _ = rand.Read(refBytes)

	resp := TokenResponse{
		AccessToken:  "ac_tok_" + hex.EncodeToString(accBytes),
		RefreshToken: "ac_ref_" + hex.EncodeToString(refBytes),
		ExpiresIn:    86400,
		TokenType:    "Bearer",
		TenantID:     authCode.TenantID,
		UserID:       authCode.UserID,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
