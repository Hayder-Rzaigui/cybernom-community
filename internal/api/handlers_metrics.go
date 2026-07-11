package api

import (
	"net/http"
	"strconv"

	"github.com/hayderrzaigui/cybernom/internal/storage"
)

// dashboardMetricsResponse bundles every widget's data into one response
// so the dashboard can populate the whole widget grid with a single fetch
// on load/refresh, rather than firing 5 separate requests every poll.
type dashboardMetricsResponse struct {
	Severity       storage.SeverityCounts    `json:"severity"`
	Status         storage.StatusCounts      `json:"status"`
	SLA            storage.SLACompliance     `json:"sla"`
	Categories     []storage.CategoryCount   `json:"categories"`
	DetectionTrend []storage.DailyCount      `json:"detection_trend"`
	SourceVolume   []storage.SourceVolumeDay `json:"source_volume"`
}

// handleDashboardMetrics powers every non-alert-table widget in the
// mockup's widget grid: severity donut, status donut, SLA donut, category
// breakdown bars, 7-day detection trend line, and per-source stacked bar.
// All values come from live aggregate queries over the alerts table (plus
// sla_targets / source_categories config) — see internal/storage/postgres.go.
//
// Deliberately not behind the same per-list audit write as
// handleListAlerts: these are aggregate counts, not individual alert
// content, so there's nothing sensitive being viewed that the audit log
// needs to attribute to a specific viewer.
func (s *Server) handleDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 90 {
			days = parsed
		}
	}

	ctx := r.Context()

	severity, err := s.store.SeverityCounts(ctx)
	if err != nil {
		s.log.Error("dashboard metrics: severity counts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	status, err := s.store.StatusCounts(ctx)
	if err != nil {
		s.log.Error("dashboard metrics: status counts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sla, err := s.store.SLACompliance(ctx)
	if err != nil {
		s.log.Error("dashboard metrics: sla compliance failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	categories, err := s.store.OpenAlertsByCategory(ctx, 8)
	if err != nil {
		s.log.Error("dashboard metrics: category counts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	trend, err := s.store.DetectionVolume(ctx, days)
	if err != nil {
		s.log.Error("dashboard metrics: detection volume failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sourceVolume, err := s.store.SourceVolumeByCategory(ctx, days)
	if err != nil {
		s.log.Error("dashboard metrics: source volume failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, dashboardMetricsResponse{
		Severity:       severity,
		Status:         status,
		SLA:            sla,
		Categories:     categories,
		DetectionTrend: trend,
		SourceVolume:   sourceVolume,
	})
}
