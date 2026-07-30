package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type UserHandler struct {
	store *store.Store
}

func NewUserHandler(s *store.Store) *UserHandler {
	return &UserHandler{store: s}
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
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
	var req CreateUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "hashing failed", http.StatusInternalServerError)
		return
	}

	u := &model.User{
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

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Password hashing utility using iterative SHA256 (for offline demo compatibility)
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := []byte(password)
	for i := 0; i < 10000; i++ {
		h := sha256.New()
		h.Write(hash)
		h.Write(salt)
		hash = h.Sum(nil)
	}
	
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	
	return fmt.Sprintf("$sha256$i=10000$%s$%s", b64Salt, b64Hash), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) < 5 || parts[1] != "sha256" {
		return false, fmt.Errorf("invalid hash format")
	}

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

	return bytes.Equal(hash, expectedHash), nil
}
