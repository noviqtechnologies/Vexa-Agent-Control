package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/session"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type PKCEAuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	DeviceJKT     string
	UserID        string
	TenantID      string
	ExpiresAt     time.Time
}

type PKCEOAuthHandler struct {
	Store     *store.Store
	jwtSecret []byte
	mu        sync.Mutex
	codes     map[string]PKCEAuthCode
}

func NewPKCEOAuthHandler(st *store.Store) *PKCEOAuthHandler {
	return &PKCEOAuthHandler{
		Store:     st,
		jwtSecret: []byte("agentcontrol-access-token-secret-change-me"),
		codes:     make(map[string]PKCEAuthCode),
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
	deviceJKT := q.Get("device_jkt")
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
		DeviceJKT:     deviceJKT,
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
	RefreshToken string `json:"refresh_token"`
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
		req.RefreshToken = r.FormValue("refresh_token")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Branch 1: Refresh Token Grant
	if req.GrantType == "refresh_token" {
		if req.RefreshToken == "" {
			http.Error(w, `{"error":"invalid_request","error_description":"missing refresh_token parameter"}`, http.StatusBadRequest)
			return
		}

		currentHasher := sha256.New()
		currentHasher.Write([]byte(req.RefreshToken))
		currentHash := hex.EncodeToString(currentHasher.Sum(nil))

		// Generate new rotating refresh token
		nextBytes := make([]byte, 32)
		_, _ = rand.Read(nextBytes)
		nextRaw := "ac_ref_" + hex.EncodeToString(nextBytes)

		nextHasher := sha256.New()
		nextHasher.Write([]byte(nextRaw))
		nextHash := hex.EncodeToString(nextHasher.Sum(nil))
		nextExpiry := time.Now().Add(30 * 24 * time.Hour)

		var userID, tenantID string
		if h.Store != nil {
			rotated, err := h.Store.RotateRefreshToken(r.Context(), currentHash, nextHash, nextExpiry)
			if err != nil {
				if errors.Is(err, store.ErrTokenReused) {
					http.Error(w, `{"error":"invalid_grant","error_description":"Refresh token reuse detected. All tokens in this family have been revoked."}`, http.StatusUnauthorized)
					return
				}
				if errors.Is(err, store.ErrTokenRevoked) || errors.Is(err, store.ErrTokenExpired) || errors.Is(err, store.ErrTokenNotFound) {
					http.Error(w, `{"error":"invalid_grant","error_description":"Refresh token is invalid, expired, or revoked."}`, http.StatusUnauthorized)
					return
				}
				http.Error(w, fmt.Sprintf(`{"error":"server_error","error_description":"%v"}`, err), http.StatusInternalServerError)
				return
			}
			userID = rotated.UserID
			tenantID = rotated.OrganizationID
		} else {
			userID = "user-refreshed"
			tenantID = middleware.DefaultOrganizationID
		}

		// Mint new access token
		accBytes := make([]byte, 32)
		_, _ = rand.Read(accBytes)
		accessToken := "ac_tok_" + hex.EncodeToString(accBytes)

		resp := TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: nextRaw,
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			TenantID:     tenantID,
			UserID:       userID,
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Branch 2: Authorization Code Grant
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

	// Resolve team membership
	teamID := "default"
	if h.Store != nil {
		if t, err := h.Store.GetUserTeam(r.Context(), authCode.TenantID, authCode.UserID); err == nil && t != "" {
			teamID = t
		}
	}

	// Generate secure refresh token family
	refBytes := make([]byte, 32)
	_, _ = rand.Read(refBytes)
	rawRefreshToken := "ac_ref_" + hex.EncodeToString(refBytes)

	if h.Store != nil {
		familyBytes := make([]byte, 16)
		_, _ = rand.Read(familyBytes)
		familyUUID := fmt.Sprintf("%x-%x-%x-%x-%x", familyBytes[0:4], familyBytes[4:6], familyBytes[6:8], familyBytes[8:10], familyBytes[10:16])

		refHasher := sha256.New()
		refHasher.Write([]byte(rawRefreshToken))
		refHash := hex.EncodeToString(refHasher.Sum(nil))

		_ = h.Store.CreateRefreshTokenFamily(r.Context(), &store.OAuthRefreshToken{
			FamilyID:       familyUUID,
			UserID:         authCode.UserID,
			OrganizationID: authCode.TenantID,
			TeamID:         teamID,
			DeviceID:       authCode.DeviceJKT,
			TokenHash:      refHash,
			ExpiresAt:      time.Now().Add(30 * 24 * time.Hour),
		})
	}

	// Mint Access Token with cnf.jkt binding if device thumbprint present
	tokenType := "Bearer"
	var accessToken string
	if authCode.DeviceJKT != "" {
		tokenType = "DPoP"
		claims := jwt.MapClaims{
			"sub":     authCode.UserID,
			"org_id":  authCode.TenantID,
			"team_id": teamID,
			"exp":     time.Now().Add(1 * time.Hour).Unix(),
			"iat":     time.Now().Unix(),
			"cnf": map[string]interface{}{
				"jkt": authCode.DeviceJKT,
			},
		}
		t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		if signed, err := t.SignedString(h.jwtSecret); err == nil {
			accessToken = signed
		}
	}

	if accessToken == "" {
		accBytes := make([]byte, 32)
		_, _ = rand.Read(accBytes)
		accessToken = "ac_tok_" + hex.EncodeToString(accBytes)
	}

	resp := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		ExpiresIn:    3600,
		TokenType:    tokenType,
		TenantID:     authCode.TenantID,
		UserID:       authCode.UserID,
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
