package api

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"time"

	"github.com/hayderrzaigui/cybernom/internal/auth"
	"github.com/hayderrzaigui/cybernom/internal/storage"
)

// exportMaxRows caps how many rows a single export request will fetch and
// stream, so an unauthenticated-limit-style query parameter can't be used
// to force an unbounded table scan / OOM. Compliance exports are expected
// to be run periodically (monthly/quarterly), not on every alert volume,
// so this ceiling is generous without being unlimited.
const exportMaxRows = 50000

// csvSafe neutralizes CSV/formula injection. Several fields written into
// these exports (alert titles, keyword names, source feed names) ultimately
// come from external feed content, which the threat model treats as hostile
// input. Spreadsheet applications (Excel, Google Sheets, LibreOffice) treat
// a cell starting with '=', '+', '-', or '@' as a formula, so a feed item
// titled e.g. `=cmd|'/c calc'!A1` could execute when an analyst opens the
// exported CSV. Prefixing such cells with a single quote is the standard
// mitigation: spreadsheet apps render it as a leading apostrophe (dropped
// from display) rather than treating the cell as a formula, while the
// underlying CSV data itself is otherwise unchanged.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}

// handleExportAlertsCSV streams alert history as CSV. Supports optional
// severity, status, and date range filters via query parameters. Only
// SOC Tier 1+, SOC Tier 2, and Compliance Auditor roles may call this
// (enforced by RequireRoles in the router); the CSV includes item
// snippets, which may contain sensitive material, hence the same care as
// handleListAlerts's audit trail below.
func (s *Server) handleExportAlertsCSV(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	severity := r.URL.Query().Get("severity")
	if severity != "" {
		switch severity {
		case "low", "medium", "high", "critical":
			// valid
		default:
			writeError(w, http.StatusBadRequest, "severity must be one of: low, medium, high, critical")
			return
		}
	}

	status := r.URL.Query().Get("status")
	if status != "" {
		switch status {
		case "new", "in_triage", "resolved":
			// valid
		default:
			writeError(w, http.StatusBadRequest, "status must be one of: new, in_triage, resolved")
			return
		}
	}

	var from, to *time.Time
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "from must be in YYYY-MM-DD format")
			return
		}
		from = &t
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "to must be in YYYY-MM-DD format")
			return
		}
		to = &t
	}

	// The storage layer only filters by severity server-side today; status
	// and date-range filtering happen here. Bound the base fetch so a wide
	// filter (e.g. status=resolved with no severity) still can't pull an
	// unbounded number of rows.
	alerts, err := s.store.ListAlerts(r.Context(), exportMaxRows, severity)
	if err != nil {
		s.log.Error("export alerts csv: list alerts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	filtered := make([]storage.Alert, 0, len(alerts))
	for _, a := range alerts {
		if status != "" && a.Status != status {
			continue
		}
		if from != nil && a.CreatedAt.Before(*from) {
			continue
		}
		if to != nil && a.CreatedAt.After(to.Add(24*time.Hour)) {
			continue
		}
		filtered = append(filtered, a)
	}

	buf := &bytes.Buffer{}
	cw := csv.NewWriter(buf)
	_ = cw.Write([]string{
		"Alert ID", "Keyword", "Severity", "Status", "Source Feed",
		"Title", "URL", "Tags", "Created At", "Resolved At", "Acknowledged",
	})
	for _, a := range filtered {
		resolvedAt := ""
		if a.ResolvedAt != nil {
			resolvedAt = a.ResolvedAt.Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			a.ID,
			csvSafe(a.KeywordName),
			a.Severity,
			a.Status,
			csvSafe(a.SourceFeed),
			csvSafe(a.ItemTitle),
			csvSafe(a.ItemURL),
			csvSafe(fmt.Sprintf("%v", a.Tags)),
			a.CreatedAt.Format(time.RFC3339),
			resolvedAt,
			fmt.Sprintf("%v", a.Acknowledged),
		})
	}
	cw.Flush()

	s.writeAudit(r, claims.UserID, claims.Username, "export.alerts_csv", "")

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cybernom-alerts-%s.csv"`, time.Now().UTC().Format("2006-01-02")))
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

// handleExportAuditLogCSV streams audit log entries as CSV. Restricted to
// SOC Tier1+ and Compliance Auditor by the router; Compliance Auditor's
// entire purpose in the role model is this endpoint plus dashboard
// metrics, so it deliberately has no other write or alert-detail access.
func (s *Server) handleExportAuditLogCSV(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entries, err := s.store.ListAudit(r.Context(), exportMaxRows, "")
	if err != nil {
		s.log.Error("export audit csv: list audit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	buf := &bytes.Buffer{}
	cw := csv.NewWriter(buf)
	_ = cw.Write([]string{"Timestamp", "Username", "Action", "Alert ID", "IP Address"})
	for _, e := range entries {
		_ = cw.Write([]string{
			e.CreatedAt.Format(time.RFC3339),
			csvSafe(e.Username),
			e.Action,
			e.AlertID,
			csvSafe(e.IPAddress),
		})
	}
	cw.Flush()

	// Exporting the audit log is itself an audit-worthy action — it's a
	// compliance artifact leaving the system, potentially to be handed to
	// an external regulator or auditor.
	s.writeAudit(r, claims.UserID, claims.Username, "export.audit_csv", "")

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cybernom-audit-%s.csv"`, time.Now().UTC().Format("2006-01-02")))
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

// SLAReport is the JSON body behind the "PDF summary" export. It's
// returned as JSON today (see handleExportPDFReport doc comment) but
// shaped to map 1:1 onto a future PDF template: total volume, MTTR, and
// SLA compliance are exactly what a security manager needs for a
// board-level or regulator-facing summary.
type SLAReport struct {
	GeneratedAt         time.Time  `json:"generated_at"`
	CoverageFrom        *time.Time `json:"coverage_from,omitempty"`
	CoverageTo          *time.Time `json:"coverage_to,omitempty"`
	MaxAlertsConsidered int        `json:"max_alerts_considered"`
	TotalAlerts         int        `json:"total_alerts"`
	CriticalAlerts      int        `json:"critical_alerts"`
	HighAlerts          int        `json:"high_alerts"`
	ResolvedAlerts      int        `json:"resolved_alerts"`
	AverageMTTR         string     `json:"average_mttr"`
	SLACompliance       float64    `json:"sla_compliance_percent"`
}

func (s *Server) handleExportPDFReport(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	alerts, err := s.store.ListAlerts(r.Context(), exportMaxRows, "")
	if err != nil {
		s.log.Error("export report: list alerts failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	sla, err := s.store.SLACompliance(r.Context())
	if err != nil {
		s.log.Error("export report: sla compliance failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	report := SLAReport{
		GeneratedAt:         time.Now().UTC(),
		MaxAlertsConsidered: exportMaxRows,
	}

	var totalMTTR time.Duration
	resolvedCount := 0
	for _, a := range alerts {
		report.TotalAlerts++
		switch a.Severity {
		case "critical":
			report.CriticalAlerts++
		case "high":
			report.HighAlerts++
		}
		if a.Status == "resolved" && a.ResolvedAt != nil {
			resolvedCount++
			totalMTTR += a.ResolvedAt.Sub(a.CreatedAt)
		}
	}
	if len(alerts) > 0 {
		newest := alerts[0].CreatedAt
		oldest := alerts[len(alerts)-1].CreatedAt
		report.CoverageTo = &newest
		report.CoverageFrom = &oldest
	}
	report.ResolvedAlerts = resolvedCount
	if resolvedCount > 0 {
		report.AverageMTTR = (totalMTTR / time.Duration(resolvedCount)).Round(time.Second).String()
	} else {
		report.AverageMTTR = "n/a"
	}
	report.SLACompliance = sla.PercentMet

	s.writeAudit(r, claims.UserID, claims.Username, "export.sla_report", "")

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cybernom-report-%s.json"`, time.Now().UTC().Format("2006-01-02")))
	writeJSON(w, http.StatusOK, report)
}
