package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/kopia/kopia/internal/apiclient"
)

// kopiaSessionCookie is the name of the session cookie that Kopia server will generate for all
// UI sessions.
const kopiaSessionCookie = "Kopia-Session-Cookie"

func (s *Server) generateCSRFToken(sessionID string) string {
	h := hmac.New(sha256.New, s.authCookieSigningKey)

	if _, err := io.WriteString(h, sessionID); err != nil {
		panic("io.WriteString() failed: " + err.Error())
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) validateCSRFToken(r *http.Request) bool {
	if s.options.DisableCSRFTokenChecks {
		return true
	}

	ctx := r.Context()
	path := r.URL.Path

	sessionCookie, err := r.Cookie(kopiaSessionCookie)
	if err != nil {
		log(ctx).Warnf("missing or invalid session cookie for %q: %v", path, err)

		return false
	}

	validToken := s.generateCSRFToken(sessionCookie.Value)

	token := r.Header.Get(apiclient.CSRFTokenHeader)
	if token == "" {
		log(ctx).Warnf("missing CSRF token for %v", path)
		return false
	}

	if subtle.ConstantTimeCompare([]byte(validToken), []byte(token)) == 1 {
		return true
	}

	log(ctx).Warnf("got invalid CSRF token for %v: %v, want %v, session %v", path, token, validToken, sessionCookie.Value)

	return false
}

func requireUIUser(_ context.Context, rc requestContext) bool {
	if rc.srv.getAuthenticator() == nil {
		return true
	}

	if rc.srv.getOptions().UIUser == "" {
		return false
	}

	user, _, _ := rc.req.BasicAuth()

	return user == rc.srv.getOptions().UIUser
}

// requireRepositoryUser allows any user that exists in the repository to access the web UI
func requireRepositoryUser(ctx context.Context, rc requestContext) bool {
	if rc.srv.getAuthenticator() == nil {
		return true
	}

	user, password, _ := rc.req.BasicAuth()
	if user == "" || password == "" {
		return false
	}

	// If repository is not connected, fall back to single user authentication
	if rc.rep == nil {
		// Fall back to single user authentication when repository is disconnected
		if rc.srv.getOptions().UIUser == "" {
			return false
		}
		return user == rc.srv.getOptions().UIUser
	}

	// Use the same authentication logic as API connections
	// This checks against repository-stored users
	authenticator := rc.srv.getAuthenticator()
	if authenticator == nil {
		return true
	}

	isValid := authenticator.IsValid(ctx, rc.rep, user, password)

	// Log repository user authentication attempts (but not the result to avoid security issues)
	if user != "" {
		log(ctx).Debugf("Repository user authentication attempt: %s", user)
	}

	return isValid
}

func requireServerControlUser(_ context.Context, rc requestContext) bool {
	if rc.srv.getAuthenticator() == nil {
		return true
	}

	if rc.srv.getOptions().ServerControlUser == "" {
		return false
	}

	user, _, _ := rc.req.BasicAuth()

	return user == rc.srv.getOptions().ServerControlUser
}

func anyAuthenticatedUser(_ context.Context, _ requestContext) bool {
	return true
}

func handlerWillCheckAuthorization(_ context.Context, _ requestContext) bool {
	return true
}

var (
	_ isAuthorizedFunc = requireUIUser
	_ isAuthorizedFunc = requireRepositoryUser
	_ isAuthorizedFunc = anyAuthenticatedUser
	_ isAuthorizedFunc = handlerWillCheckAuthorization
)
