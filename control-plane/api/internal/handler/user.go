package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type UserHandler struct {
	store *store.Store
}

func NewUserHandler(s *store.Store) *UserHandler {
	return &UserHandler{store: s}
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	users, err := h.store.ListUsers(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

type CreateUserReq struct {
	AuthProviderID string `json:"auth_provider_id"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	IsAdmin        bool   `json:"is_admin"`
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	var req CreateUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	var hash string
	if req.Password != "" {
		var err error
		hash, err = hashPassword(req.Password)
		if err != nil {
			http.Error(w, "hashing failed", http.StatusInternalServerError)
			return
		}
	}

	u := &model.User{
		TenantID:       tenantID,
		AuthProviderID: req.AuthProviderID,
		Email:          req.Email,
		PasswordHash:   hash,
		IsAdmin:        req.IsAdmin,
	}

	if err := h.store.UpsertUser(r.Context(), u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(u)
}

type UpdatePasswordReq struct {
	Password string `json:"password"`
}

func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	id := chi.URLParam(r, "id")
	var req UpdatePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "invalid password request", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "hashing failed", http.StatusInternalServerError)
		return
	}

	if err := h.store.UpdateUserPassword(r.Context(), tenantID, id, hash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.TenantIDFromContext(r.Context())
	id := chi.URLParam(r, "id")

	targetUser, err := h.store.GetUserByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if targetUser == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if targetUser.IsAdmin || targetUser.IsSaaSOperator {
		http.Error(w, "admin role users cannot be deleted", http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteUser(r.Context(), tenantID, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// hashPassword hashes a plaintext password using bcrypt (cost=12, cryptographic adaptive salt).
// This conforms to NIST Special Publication 800-63B and OWASP password storage best practices.
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// VerifyPassword verifies a plaintext password against a stored bcrypt (or legacy sha256) hash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	if encodedHash == "" || password == "" {
		return false, nil
	}

	// 1. Standard Bcrypt verification ($2a$, $2b$, $2y$)
	if strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$") || strings.HasPrefix(encodedHash, "$2y$") {
		err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}

	// 2. Legacy SHA256 fallback compatibility with constant-time comparison
	parts := strings.Split(encodedHash, "$")
	if len(parts) >= 5 && parts[1] == "sha256" {
		var iterations int
		_, err := fmt.Sscanf(parts[2], "i=%d", &iterations)
		if err != nil || iterations <= 0 {
			iterations = 10000
		}

		b64Salt := parts[3]
		b64Hash := parts[4]

		salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
		if err != nil {
			return false, err
		}

		expectedHash, err := base64.RawStdEncoding.DecodeString(b64Hash)
		if err != nil {
			return false, err
		}

		hash := []byte(password)
		for i := 0; i < iterations; i++ {
			h := sha256.New()
			h.Write(hash)
			h.Write(salt)
			hash = h.Sum(nil)
		}

		return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
	}

	return false, fmt.Errorf("unsupported password hash format")
}

