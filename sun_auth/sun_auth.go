// may add fasthttprouter package for routing
package sun_auth

import (
	"encoding/hex"
	"log"
	"path"

	"crypto/sha256"
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
	DBUrl       string
}

type sunAuth struct {
	signer     jose.Signer
	jwk        []byte
	sunAccount *sunAccount

	Config SunAuthConfig
}

type sunAuthCustomInfo struct {
	OpenId string
}

type sunAuthClaims struct {
	*jwt.Claims
	*sunAuthCustomInfo
}

type sunTokenResponse struct {
	Token  string
	OpenId string
}

func (sj *sunAuth) router(ctx *fasthttp.RequestCtx) {
	request := &sunAuthRequest{
		sj:        sj,
		startTime: time.Now(),
	}
	request.ctx = ctx

	switch string(request.ctx.Path()) {

	case "/create_project":
		sj.createProject(request)

	case "/register":
		sj.register(request)

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

// create new project
func (sj *sunAuth) createProject(req *sunAuthRequest) {
	requestData := &sunNewProjectRequest{}
	if req.parseRequestData(requestData) != nil {
		return
	}

	if p, _ := sj.sunAccount.GetProjectByPid(requestData.ProjectId); p != nil {
		req.responseBadRequest("project already exists")
		return
	}

	proj := &Project{
		ProjectId:   requestData.ProjectId,
		ProjectName: requestData.ProjectName,
		Secret:      RandomPassword(32),
	}
	error := sj.sunAccount.NewProject(proj)

	if error != nil {
		req.responseBadRequest("invalid request")
		log.Printf("cannot create project: %v", error)
		return
	}
	req.responseOK(proj)
	log.Printf("project has been created: %v", proj)
}

// register new user
func (sj *sunAuth) register(req *sunAuthRequest) {
	requestData := &sunUserRequest{}
	if req.parseRequestData(requestData) != nil {
		return
	}

	proj, err := sj.sunAccount.GetProjectByPid(requestData.ProjectId)
	if err != nil || proj.Secret != requestData.ProjectSecret {
		req.responseBadRequest("wrong project info")
		log.Printf("wrong project info :: %v", err)
		return
	}

	user := &User{
		ProjectId: requestData.ProjectId,
		Username:  requestData.Username,
		Id:        GenUUID(),
	}

	sha := sha256.New()
	sha.Write([]byte(user.Id + requestData.UserPass))
	user.Password = hex.EncodeToString(sha.Sum(nil))

	err = sj.sunAccount.NewUser(user)
	if err != nil {
		req.responseBadRequest("cannot create user")
		log.Printf("cannot create user :: %v", err)
		return
	}

	req.responseOK(nil)
	log.Printf("new user has been created, uuid: %s", user.Id)
}

// fetch JWK
func (sj *sunAuth) fetchJwk(req *sunAuthRequest) {
	req.ctx.SetBody(sj.jwk)
}

// fetch token
func (sj *sunAuth) fetchToken(req *sunAuthRequest) {
	requestData := &sunUserRequest{}
	if req.parseRequestData(requestData) != nil {
		return
	}

	claims := &sunAuthClaims{
		Claims: &jwt.Claims{
			Issuer:   sj.Config.Issuer,
			Audience: jwt.Audience{requestData.ProjectId},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		},
		sunAuthCustomInfo: &sunAuthCustomInfo{
			OpenId: "test_openid",
		},
	}

	sign, error := jwt.Signed(sj.signer).Claims(claims).CompactSerialize()
	if error != nil {
		log.Printf("cannot sign claims :: %v", error)
		req.responseServerError("server error")
		return
	}

	req.responseOK(&sunTokenResponse{
		Token:  sign,
		OpenId: "test_openid",
	})
}

func (sj *sunAuth) NewAccount() {
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
	sc := NewSunAccount(sj.Config.DBUrl)
	sc.InitDB()
	sj.sunAccount = sc
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
			DBUrl:       "postgres://Kevin:1997@localhost:5432/sun_account?sslmode=disable",
		},
	}
}
