package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hayderrzaigui/cybernom/internal/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// handleLogin authenticates username/password and issues a token pair.
// Deliberately returns an identical "invalid credentials" response whether
// the username doesn't exist or the password is wrong — no username
// enumeration via response differences or timing (bcrypt comparison runs
// either way via VerifyPassword against a real-or-dummy hash).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	const dummyHash = "$2a$12$C6UzMDM.H6dfI/f/IKcEeO0rQvcQ9pk9qC9K8x4t.7g2n1e8FQzFC" // never a valid match

	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	hashToCheck := dummyHash
	if err == nil {
		hashToCheck = user.PasswordHash
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error("login: user lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	verifyErr := auth.VerifyPassword(hashToCheck, req.Password)
	if err != nil || verifyErr != nil {
		s.writeAudit(r, "", req.Username, "auth.login_failed", "")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	accessToken, err := s.tokens.IssueAccessToken(user.ID, user.Username, auth.Role(user.Role))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	refreshToken, err := s.tokens.IssueRefreshToken(user.ID, user.Username, auth.Role(user.Role))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	s.writeAudit(r, user.ID, user.Username, "auth.login", "")

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claims, err := s.tokens.Verify(req.RefreshToken, "refresh")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	// Re-fetch the user rather than trusting the role/identity embedded in
	// the refresh token: a refresh token can be up to refresh_token_ttl old
	// (default 7 days), so if the account was deleted or its role changed
	// since the token was issued, re-signing the token's stale claims would
	// silently keep a demoted/removed user's old privileges alive for the
	// rest of that window. Looking the user up here means a role change or
	// deletion takes effect on the very next refresh, not up to 7 days later.
	user, err := s.store.GetUserByUsername(r.Context(), claims.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	if user.ID != claims.UserID {
		// Username was reused for a different account after the original
		// user was deleted; treat the same as "account no longer exists".
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	accessToken, err := s.tokens.IssueAccessToken(user.ID, user.Username, auth.Role(user.Role))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	})
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// handleCreateUser is admin-only (enforced by RequireRole in the router).
// Valid role strings come from auth.AllRoles(), which resolves to the
// Community two-role set or the Enterprise four-role set depending on how
// the binary was built — this handler is identical either way.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	valid := false
	names := make([]string, 0, len(auth.AllRoles()))
	for _, role := range auth.AllRoles() {
		names = append(names, string(role))
		if req.Role == string(role) {
			valid = true
		}
	}
	if !valid {
		writeError(w, http.StatusBadRequest, "role must be one of: "+strings.Join(names, ", "))
		return
	}

	hash, err := auth.HashPassword(req.Password, s.cfg.Auth.BcryptCost)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := s.store.CreateUser(r.Context(), req.Username, hash, req.Role)
	if err != nil {
		s.log.Error("create user failed", "error", err)
		writeError(w, http.StatusConflict, "could not create user (username may already exist)")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}
