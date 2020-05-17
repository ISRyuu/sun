// may add fasthttprouter package for routing
package sun_auth

import (
	"log"
	"path"

	"fmt"
	"io/ioutil"
	"time"

	"github.com/valyala/fasthttp"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type SunAuthConfig struct {
	PubKeyPath  string
	PrivKeyPath string
	Issuer      string
}

type sunAuth struct {
	signer jose.Signer
	jwk    []byte
	Config SunAuthConfig
}

// project
type sunAuthProject struct {
	ClientId string
	Secret   string
}

type fetchTokenRequest struct {
	sunAuthProject
}

type refreshTokenRequest struct {
	sunAuthProject
	RefreshToken string
}

type SunAuthCustomInfo struct {
	OpenId string
}

type SunAuthClaims struct {
	*jwt.Claims
	SunAuthCustomInfo
}

type SunTokenResponse struct {
	Token string `json:"token"`
}

func (sj *sunAuth) router(ctx *fasthttp.RequestCtx) {
	request := &sunAuthRequest{
		sj:        sj,
		startTime: time.Now(),
	}
	request.ctx = ctx

	switch string(request.ctx.Path()) {

	case "/register":
		sj.fetchJwk(request)

	case "/jwk":
		sj.fetchJwk(request)

	case "/fetch_token":
		sj.fetchToken(request)

	case "/refresh_token":
		sj.refreshToken(request)

	default:
		ctx.Error("not found", fasthttp.StatusNotFound)
	}

	log.Printf("%s %s %s %d %.2fms\n",
		ctx.RemoteIP(),
		ctx.URI(),
		ctx.Method(),
		ctx.Response.StatusCode(),
		float64(time.Since(request.startTime).Nanoseconds())/float64(10e6),
	)
}

// fetch JWK
func (sj *sunAuth) fetchJwk(req *sunAuthRequest) {
	req.ctx.SetBody(sj.jwk)
}

// fetch token
func (sj *sunAuth) fetchToken(req *sunAuthRequest) {
	requestData := &fetchTokenRequest{}
	if req.parseRequestData(requestData) != nil {
		return
	}

	claims := &SunAuthClaims{
		Claims: &jwt.Claims{
			Issuer:   sj.Config.Issuer,
			Audience: jwt.Audience{requestData.ClientId},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		},
		SunAuthCustomInfo: SunAuthCustomInfo{
			OpenId: "test_openid",
		},
	}

	sign, error := jwt.Signed(sj.signer).Claims(claims).CompactSerialize()
	if error != nil {
		log.Printf("cannot sign claims :: %v", error)
		req.responseServerError("server error")
		return
	}

	req.responseOK(&SunTokenResponse{
		Token: sign,
	})
}

// refresh token
func (sj *sunAuth) refreshToken(req *sunAuthRequest) {
}

// initialize jwk
func (sj *sunAuth) initJwk() {
	// load private key
	bytes, error := ioutil.ReadFile(sj.Config.PrivKeyPath)
	fatal(error, fmt.Sprintf("can not load key: %s :: ", sj.Config.PrivKeyPath))

	signKey, error := ParseRSAPrivateKeyFromPEM(bytes)
	fatal(error, fmt.Sprintf("cannot parse private key: %s", sj.Config.PrivKeyPath))

	// kid is the filename of the private keyfile
	ext := path.Ext(sj.Config.PrivKeyPath)
	baseName := path.Base(sj.Config.PrivKeyPath)
	kid := baseName[:len(baseName)-len(ext)]

	signer, error := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	fatal(error, "cannot create signer")	

	// load public key
	bytes, error = ioutil.ReadFile(sj.Config.PubKeyPath)
	fatal(error, fmt.Sprintf("can not load pub key: %s", sj.Config.PubKeyPath))

	pubKey, error := ParseRSAPublicKeyFromPEM(bytes)
	fatal(error, fmt.Sprintf("cannot parse public key: %s", sj.Config.PubKeyPath))

	jwk := jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
	}

	jwkJson, error := jwk.MarshalJSON()
	fatal(error, "cannot marshal jwk")

	sj.signer = signer
	sj.jwk = jwkJson

	log.Printf("loaded key pair kid=%s\n", kid)
}

// run server
func (sj *sunAuth) Forever(addr string) {
	sj.initJwk()
	if err := fasthttp.ListenAndServe(addr, sj.router); err != nil {
		fatal(err, "cannot start server")
	}
}

// generate a new sun auth server
func NewSunJwt() *sunAuth {
	return &sunAuth{
		Config: SunAuthConfig{
			PubKeyPath:  "keys/test.pub",
			PrivKeyPath: "keys/test",
			Issuer:      "sun-auth",
		},
	}
}
