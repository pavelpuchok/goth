package donationalerts

import (
	"bytes"
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

const (
	// ScopeUserShow provide access to obtain user profile information.
	ScopeUserShow string = "oauth-user-show"
	// ScopeDonationIndex provide access to obtain user donation alerts list.
	ScopeDonationIndex string = "oauth-donation-index"
	// ScopeDonationSubscribe provide access to subscribe for new donation alerts.
	ScopeDonationSubscribe string = "oauth-donation-subscribe"
)

const (
	authEndpoint    string = "https://www.donationalerts.com/oauth/authorize"
	tokenEndpoint   string = "https://www.donationalerts.com/oauth/token"
	profileEndpoint string = "https://www.donationalerts.com/api/v1/user/oauth"
)

// New creates a new DonationAlerts provider, and sets up important connection details.
// You should always call `donationalerts.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:       clientKey,
		Secret:          secret,
		CallbackURL:     callbackURL,
		providerName:    "donationalerts",
		ProfileEndpoint: profileEndpoint,
	}
	p.config = newConfig(p, scopes)
	return p

}

// Provider is the implementation of `goth.Provider` for accessing DonationAlerts.
type Provider struct {
	ClientKey       string
	Secret          string
	CallbackURL     string
	HTTPClient      *http.Client
	config          *oauth2.Config
	providerName    string
	ProfileEndpoint string
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// BeginAuth asks DonationAlerts for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	s := &Session{
		AuthURL: url,
	}
	return s, nil
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

// FetchUser obtains basic info about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)

	bits, err := p.fetchUserData(s.AccessToken)

	if err != nil {
		return goth.User{}, err
	}

	user := goth.User{
		Provider:     p.Name(),
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	err = decodeUserData(bits, &user)

	return user, err
}

func (p *Provider) fetchUserData(accessToken string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, p.ProfileEndpoint, nil)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	r, err := p.Client().Do(req)

	if err != nil {
		return []byte{}, err
	}

	defer r.Body.Close()

	bits, err := ioutil.ReadAll(r.Body)
	return bits, err
}

// Debug is no-op for the DonationAlerts package.
func (p *Provider) Debug(bool) {}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// Client to be used in all fetch operations
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
		RedirectURL: p.CallbackURL,
		Scopes:      []string{},
	}

	if len(scopes) > 0 {
		for _, s := range scopes {
			config.Scopes = append(config.Scopes, s)
		}
	} else {
		config.Scopes = []string{ScopeUserShow}
	}

	return config
}

func decodeUserData(bits []byte, user *goth.User) error {
	var err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return err
	}

	profile := struct {
		Data struct {
			Id                     int64  `json:"id"`
			Code                   string `json:"code"`
			Name                   string `json:"name"`
			Avatar                 string `json:"avatar"`
			Email                  string `json:"email"`
			SocketConnectionString string `json:"socket_connection_string"`
		} `json:"data"`
	}{}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&profile)
	if err != nil {
		return err
	}

	user.Name = profile.Data.Name
	user.NickName = profile.Data.Code
	user.Email = profile.Data.Email
	user.UserID = strconv.FormatInt(profile.Data.Id, 10)
	user.AvatarURL = profile.Data.Avatar

	return nil
}
