package sun_auth

import (
	"encoding/json"
	"fmt"

	"time"

	"github.com/valyala/fasthttp"
)

type sunAuthRequest struct {
	ctx       *fasthttp.RequestCtx
	sj        *sunAuth
	startTime time.Time
}

type sunResponse struct {
	Msg  string        `json:"msg"`
	Code sunStatusCode `json:"code"`
	Data interface{}   `json:"data,omitempty"`
}

type Validable interface {
	Validate() error
}

// request structure BEGIN
type sunUserRequest struct {
	Username string
	UserPass string
	sunProjectRequest
}

func (r *sunUserRequest) Validate() error {
	if len(r.Username) == 0 || len(r.Username) > 16 {
		return fmt.Errorf("the length of Username must be between 1 and 16")
	}

	if len(r.UserPass) < 6 || len(r.UserPass) > 64 {
		return fmt.Errorf("the length of UserPass must be between 6 and 64")
	}

	return r.sunProjectRequest.Validate()
}

type sunNewProjectRequest struct {
	ProjectName string
	ProjectId   string
}

func (r *sunNewProjectRequest) Validate() error {
	if len(r.ProjectName) == 0 || len(r.ProjectName) > 16 {
		return fmt.Errorf("the length of ProjectName must be between 1 and 16")
	}

	if len(r.ProjectId) == 0 || len(r.ProjectId) > 16 {
		return fmt.Errorf("the length of ProjectId must be between 1 and 16")
	}

	return nil
}

type sunProjectRequest struct {
	ProjectId     string
	ProjectSecret string
}

func (r *sunProjectRequest) Validate() error {
	if len(r.ProjectId) == 0 || len(r.ProjectId) > 16 {
		return fmt.Errorf("invalid ProjectId")
	}
	return nil
}

type sunRefreshTokenRequest struct {
	sunProjectRequest
	RefreshToken string
}

func (r *sunRefreshTokenRequest) Validate() error {
	return r.sunProjectRequest.Validate()
}

// request structure END

// parser request data, unmarshal json
func (req *sunAuthRequest) parseRequestData(v Validable) error {
	error := json.Unmarshal(req.ctx.Request.Body(), v)
	if error == nil {
		error = v.Validate()
	}

	if error != nil {
		response := sunResponse{
			Msg:  error.Error(),
			Code: SunBadRequest,
		}
		responseData, _ := json.Marshal(response)
		req.ctx.SetStatusCode(fasthttp.StatusBadRequest)
		req.ctx.SetBody(responseData)
		return error
	}
	return nil
}

// send 200 OK response with data
func (req *sunAuthRequest) responseOK(data interface{}) {
	response := sunResponse{
		Msg:  "ok",
		Code: SunOK,
		Data: data,
	}
	responseData, _ := json.Marshal(response)
	req.ctx.SetBody(responseData)
}

// send 500 server error with additional error info
func (req *sunAuthRequest) responseServerError(error string) {
	response := sunResponse{
		Msg:  error,
		Code: ServerError,
	}
	responseData, _ := json.Marshal(response)
	req.ctx.SetStatusCode(fasthttp.StatusInternalServerError)
	req.ctx.SetBody(responseData)
}

// send 400 error with additional error info
func (req *sunAuthRequest) responseBadRequest(error string) {
	response := sunResponse{
		Msg:  error,
		Code: BadRequest,
	}
	responseData, _ := json.Marshal(response)
	req.ctx.SetStatusCode(fasthttp.StatusBadRequest)
	req.ctx.SetBody(responseData)
}

// send 401 error with additional error info
func (req *sunAuthRequest) responseUnauthorized(error string) {
	response := sunResponse{
		Msg:  error,
		Code: BadRequest,
	}
	responseData, _ := json.Marshal(response)
	req.ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	req.ctx.SetBody(responseData)
}
