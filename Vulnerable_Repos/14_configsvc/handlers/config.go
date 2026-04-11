package handlers

import (
	"configsvc/db"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

type ConfigHandler struct {
	store *db.Store
}

type ConfigEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ReloadRequest struct {
	Command string `json:"command"`
}

func NewConfigHandler(s *db.Store) *ConfigHandler {
	return &ConfigHandler{store: s}
}

func (h *ConfigHandler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "key parameter required", http.StatusBadRequest)
			return
		}
		value, err := h.store.GetConfig(key)
		if err != nil {
			http.Error(w, fmt.Sprintf("lookup failed: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(ConfigEntry{Key: key, Value: value})

	case http.MethodPost:
		var entry ConfigEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := h.store.SetConfig(entry.Key, entry.Value); err != nil {
			http.Error(w, fmt.Sprintf("store failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(entry)

	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if err := h.store.DeleteConfig(key); err != nil {
			http.Error(w, fmt.Sprintf("delete failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ConfigHandler) HandleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "path parameter required", http.StatusBadRequest)
		return
	}
	count, err := h.store.ImportFromFile(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("import failed: %v", err), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]int{"imported": count})
}

func (h *ConfigHandler) HandleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ReloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("sh", "-c", req.Command).CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
