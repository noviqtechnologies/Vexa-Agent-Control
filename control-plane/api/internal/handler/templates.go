package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type TemplateHandler struct {
	store *store.Store
}

func NewTemplateHandler(s *store.Store) *TemplateHandler {
	return &TemplateHandler{store: s}
}

func (h *TemplateHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := h.store.ListTemplates(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if templates == nil {
		templates = []*model.PolicyTemplate{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

func (h *TemplateHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "template id required", http.StatusBadRequest)
		return
	}

	tpl, err := h.store.GetTemplateByID(r.Context(), id)
	if err != nil || tpl == nil {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tpl)
}

func (h *TemplateHandler) CreateCustomTemplate(w http.ResponseWriter, r *http.Request) {
	var tpl model.PolicyTemplate
	if err := json.NewDecoder(r.Body).Decode(&tpl); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(tpl.ID) == "" || strings.TrimSpace(tpl.Name) == "" || strings.TrimSpace(tpl.Content) == "" {
		http.Error(w, "id, name, and content are required", http.StatusBadRequest)
		return
	}

	if err := h.store.SaveCustomTemplate(r.Context(), &tpl); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tpl)
}

func (h *TemplateHandler) DeleteCustomTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "template id required", http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteCustomTemplate(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
