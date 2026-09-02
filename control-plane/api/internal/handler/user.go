package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
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

	var authProvPtr *string
	if req.AuthProviderID != "" {
		authProvPtr = &req.AuthProviderID
	}
	role := "MEMBER"
	if req.IsAdmin {
		role = "ADMIN"
	}
	u := &model.User{
		OrganizationID: tenantID,
		AuthProviderID: authProvPtr,
		Email:          req.Email,
		PasswordHash:   hash,
		IsAdmin:        req.IsAdmin,
		Role:           role,
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
	claims := middleware.UserClaimsFromContext(r.Context())
	id := chi.URLParam(r, "id")

	// Authorization check: users can only update their own password unless they hold admin role
	if claims != nil && claims.UserID != id && !claims.IsAdmin {
		http.Error(w, `{"error":"forbidden: admin privileges required to update other users' passwords"}`, http.StatusForbidden)
		return
	}

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
	if targetUser.IsAdmin {
		http.Error(w, "admin role users cannot be deleted", http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

