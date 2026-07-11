package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hayderrzaigui/cybernom/internal/auth"
	"github.com/hayderrzaigui/cybernom/internal/storage"
)

// handleListFeeds returns all threat feeds. Available to any authenticated
// user (read-only) so analysts can see what's currently being monitored;
// only creation/toggling/deletion are role-restricted (see router.go).
func (s *Server) handleListFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.store.ListFeeds(r.Context())
	if err != nil {
		s.log.Error("list feeds failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, feeds)
}

func (s *Server) handleGetFeed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	feed, err := s.store.GetFeed(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "feed not found")
		return
	}
	writeJSON(w, http.StatusOK, feed)
}

func (s *Server) handleGetFeedStats(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	stats, err := s.store.FeedStats(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no poll history for this feed")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleToggleFeed enables or disables a feed instantly — the "one-click"
// part of feed management: no config edit, no restart. Restricted to SOC
// Tier 2 and Admin by the router.
func (s *Server) handleToggleFeed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	enabled := r.URL.Query().Get("enabled") == "true"

	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	feed, err := s.store.SetFeedEnabled(r.Context(), id, enabled)
	if err != nil {
		writeError(w, http.StatusNotFound, "feed not found")
		return
	}

	action := "feed.disabled"
	if enabled {
		action = "feed.enabled"
	}
	s.writeAudit(r, claims.UserID, claims.Username, action, "")

	writeJSON(w, http.StatusOK, feed)
}

type createFeedRequest struct {
	Name          string   `json:"name"`
	FeedType      string   `json:"feed_type"` // rss | api | website | onion
	URL           string   `json:"url"`
	PollInterval  string   `json:"poll_interval"` // Go duration string, e.g. "6h"
	Tags          []string `json:"tags"`
	RequireTor    bool     `json:"require_tor"`
	APIMethod     string   `json:"api_method,omitempty"`
	APIAuthHeader string   `json:"api_auth_header,omitempty"`
	APIDataPath   string   `json:"api_data_path,omitempty"`
}

// handleCreateFeed is admin-only (enforced by RequireRole in the router).
func (s *Server) handleCreateFeed(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req createFeedRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.URL == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}
	switch req.FeedType {
	case "rss", "api", "website", "onion":
		// valid
	default:
		writeError(w, http.StatusBadRequest, "feed_type must be one of: rss, api, website, onion")
		return
	}

	interval := 6 * time.Hour
	if req.PollInterval != "" {
		parsed, err := time.ParseDuration(req.PollInterval)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "poll_interval must be a valid positive duration, e.g. '6h'")
			return
		}
		interval = parsed
	}

	feed, err := s.store.CreateFeed(r.Context(), storage.CreateFeedParams{
		Name:          req.Name,
		FeedType:      req.FeedType,
		URL:           req.URL,
		PollInterval:  interval,
		Tags:          req.Tags,
		RequireTor:    req.RequireTor,
		APIMethod:     req.APIMethod,
		APIAuthHeader: req.APIAuthHeader,
		APIDataPath:   req.APIDataPath,
	})
	if err != nil {
		s.log.Error("create feed failed", "error", err)
		writeError(w, http.StatusConflict, "could not create feed (name may already exist)")
		return
	}

	s.writeAudit(r, claims.UserID, claims.Username, "feed.created", "")

	writeJSON(w, http.StatusCreated, feed)
}

// handleDeleteFeed is admin-only (enforced by RequireRole in the router).
func (s *Server) handleDeleteFeed(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := s.store.DeleteFeed(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "feed not found")
		return
	}

	s.writeAudit(r, claims.UserID, claims.Username, "feed.deleted", "")

	w.WriteHeader(http.StatusNoContent)
}
