package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	amodels "github.com/abhinavxd/libredesk/internal/auth/models"
	"github.com/abhinavxd/libredesk/internal/envelope"
	"github.com/abhinavxd/libredesk/internal/user/models"
	realip "github.com/ferluci/fast-realip"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
)

// tokenLoginRequest is a trusted-service assertion: the control-plane proves
// a user authenticated against Keycloak (the tenant portal's SSO) by signing
// "agent_id|expires_at" with the shared LIBREDESK_SSO_TOKEN_SECRET.
type tokenLoginRequest struct {
	AgentID   int    `json:"agent_id"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

// maxTokenLoginTTL bounds how far into the future an assertion may claim;
// the control-plane issues 60-second ones, so anything beyond this window
// is not ours.
const maxTokenLoginTTL = 300 * time.Second

// handleTokenLogin exchanges a control-plane-signed assertion for a full
// agent session (cookie pair), mirroring handleLogin minus the password
// check. The HMAC is the authentication: the route is deliberately not
// behind auth() or rateLimit — its callers are trusted internal services,
// not browsers, and rate limits keyed on their single IP would only reject
// legitimate bursts.
func handleTokenLogin(r *fastglue.Request) error {
	var (
		app = r.Context.(*App)
		ip  = realip.FromRequest(r.RequestCtx)
		req tokenLoginRequest
	)

	secret := os.Getenv("LIBREDESK_SSO_TOKEN_SECRET")
	if secret == "" {
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError,
			"token login is not configured on this instance", nil))
	}

	if err := r.Decode(&req, "json"); err != nil {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest,
			app.i18n.T("errors.parsingRequest"), nil, envelope.InputError)
	}
	if req.AgentID == 0 || req.ExpiresAt == 0 || req.Signature == "" {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest,
			app.i18n.T("globals.messages.badRequest"), nil, envelope.InputError)
	}

	now := time.Now().UTC()
	exp := time.Unix(req.ExpiresAt, 0).UTC()
	if exp.Before(now) || exp.After(now.Add(maxTokenLoginTTL)) {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest,
			"token expired or outside its validity window", nil, envelope.InputError)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d|%d", req.AgentID, req.ExpiresAt)
	want, err := hex.DecodeString(req.Signature)
	if err != nil {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest,
			app.i18n.T("globals.messages.badRequest"), nil, envelope.InputError)
	}
	if !hmac.Equal(want, mac.Sum(nil)) {
		return sendErrorEnvelope(r, envelope.NewError(envelope.InputError,
			"invalid token signature", nil))
	}

	user, err := app.user.Get(req.AgentID, "", []string{models.UserTypeAgent})
	if err != nil {
		return sendErrorEnvelope(r, err)
	}
	if !user.Enabled {
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError,
			app.i18n.T("user.accountDisabled"), nil))
	}

	if err := app.auth.SaveSession(amodels.User{
		ID:        user.ID,
		Email:     user.Email.String,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}, r); err != nil {
		app.lo.Error("error saving session", "error", err)
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError,
			app.i18n.T("globals.messages.somethingWentWrong"), nil))
	}
	if err := app.auth.SetCSRFCookie(r); err != nil {
		app.lo.Error("error setting csrf cookie", "error", err)
		return sendErrorEnvelope(r, envelope.NewError(envelope.GeneralError,
			app.i18n.T("globals.messages.somethingWentWrong"), nil))
	}
	if err := app.user.UpdateLastLoginAt(user.ID); err != nil {
		return sendErrorEnvelope(r, err)
	}
	app.user.InvalidateAgentCache(user.ID)
	if err := app.activityLog.Login(user.ID, user.Email.String, ip); err != nil {
		app.lo.Error("error creating login activity log", "error", err)
	}
	return r.SendEnvelope(user)
}
