package websocketproxy

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt"
)

type OidcConfig struct {
	jwkUrl      string
	aud         string
	tokenPrefix string
}

func (wp *WebsocketProxy) ValidateJWT(writer http.ResponseWriter, request *http.Request) error {
	jwtToken, ok := request.Header["Authorization"]

	if !ok {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Missing authorization header"))
		return errors.New("Missing authorization header")
	}

	idToken := strings.Join(jwtToken, " ")

	if len(idToken) < len(wp.oidc.tokenPrefix) || !strings.HasPrefix(idToken, wp.oidc.tokenPrefix+" ") {
		log.Println("Bad token prefix")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Bad token prefix"))
		return errors.New("Bad token prefix")
	}

	idToken = strings.ReplaceAll(idToken, " ", "")
	idToken = idToken[utf8.RuneCountInString(wp.oidc.tokenPrefix):]

	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(idToken, claims, nil)

	// is that secure???
	if len(wp.oidc.aud) == 0 {
		wp.oidc.aud = claims["aud"].(string)
	}

	oidcConfig := oidc.Config{
		ClientID: wp.oidc.aud,
	}

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, wp.oidc.jwkUrl)
	if err != nil {
		log.Println(err)
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Bad token validator url"))
		return errors.New("Bad token validator url")
	}

	verifier := provider.Verifier(&oidcConfig)

	// is that enough???
	_, err = verifier.Verify(ctx, idToken)
	if err != nil {
		log.Println(err)
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("Bad token validator url"))
		return errors.New("Bad token validator url")
	}

	wp.authHeaders(writer, request, claims)

	return nil
}
