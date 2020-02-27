package donationalerts

import (
	"encoding/json"
	"errors"
	"github.com/markbates/goth"
	"time"
)

// Session stores data during the auth process with DonationAlerts
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on
// the DonationAlerts provider.
func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Marshal the session into a string
func (s *Session) Marshal() string {
	j, _ := json.Marshal(s)
	return string(j)
}

// Authorize completes the authorization with DonationAlerts and returns the
// access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}
