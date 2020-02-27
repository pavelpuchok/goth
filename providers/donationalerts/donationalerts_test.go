package donationalerts

import (
	"fmt"
	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func provider() *Provider {
	return New("donationalerts_key", "donationalerts_secret", "/foo")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := provider()
	a.Equal(provider.ClientKey, "donationalerts_key")
	a.Equal(provider.Secret, "donationalerts_secret")
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_ImplementsProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_Name(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	a.Equal(p.Name(), "donationalerts")
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := provider()
	provider.SetName("custom_name")
	a.Equal(provider.Name(), "custom_name")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "donationalerts.com/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", "donationalerts_key"))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=oauth-user-show")
	a.Contains(s.AuthURL, "response_type=code")
}

func TestProvider_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.Equal(r.Method, "GET")
		a.Equal(r.Header.Get("Authorization"), "Bearer TOKEN")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(testProfileResponseData))
	}))
	defer ts.Close()

	p := provider()
	p.ProfileEndpoint = ts.URL
	s := &Session{
		AccessToken:  "TOKEN",
		RefreshToken: "REFRESH_TOKEN",
		ExpiresAt:    time.Now().AddDate(0, 0, 1),
	}
	user, err := p.FetchUser(s)

	a.NoError(err)
	a.Equal(user.Name, "Tris_the_Jam_Master")
	a.Equal(user.UserID, "3")
	a.Equal(user.Email, "sergey@donationalerts.com")
	a.Equal(user.AvatarURL, "https://static-cdn.jtvnw.net/jtv_user_pictures/tris_the_jam_master-profile_image-c084755ce36ab72b-300x300.jpeg")
	data := user.RawData["data"].(map[string]interface{})
	a.Equal(data["socket_connection_token"], "yeJ0eXTYOiJKV1RiLCKhbGciOiJIU4.iJIUfeyJzdeyJzd.GciJIUfiOas_FCvQTYAA8usfsTYYFD")
	a.Equal(user.Provider, "donationalerts")
	a.Equal(user.AccessToken, "TOKEN")
	a.Equal(user.RefreshToken, "REFRESH_TOKEN")
	a.Equal(user.ExpiresAt, s.ExpiresAt)
}

const testProfileResponseData = `{
    "data": {
        "id": 3,
        "code": "tris_the_jam_master",
        "name": "Tris_the_Jam_Master",
        "avatar": "https://static-cdn.jtvnw.net/jtv_user_pictures/tris_the_jam_master-profile_image-c084755ce36ab72b-300x300.jpeg",
        "email": "sergey@donationalerts.com",
        "socket_connection_token": "yeJ0eXTYOiJKV1RiLCKhbGciOiJIU4.iJIUfeyJzdeyJzd.GciJIUfiOas_FCvQTYAA8usfsTYYFD"
    }
}`
