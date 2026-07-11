//go:build !enterprise

package auth

// Community Edition role model: two roles, matching the original
// pre-RBAC-expansion design (see README's API table). Enterprise Edition
// widens this to four roles — see roles_enterprise.go — but the two role
// names below (RoleAdmin, RoleViewer) are stable across both editions:
// migration 0003 downgrades `viewer` accounts to `soc_tier1` on the
// Enterprise schema, but a Community-only deployment never applies that
// migration and keeps using RoleViewer directly.
const (
	RoleAdmin  Role = "admin"  // Full access: manage users, feeds, and view everything
	RoleViewer Role = "viewer" // Read-only: alerts, dashboard metrics, feed visibility
)

// AllRoles lists every role recognized by this build, used by handlers that
// validate a role string from user input (e.g. POST /api/v1/users).
func AllRoles() []Role {
	return []Role{RoleAdmin, RoleViewer}
}
