package sun_auth

import (
	"encoding/json"

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

// parser request data, unmarshal json
func (req *sunAuthRequest) parseRequestData(v interface{}) error {
	error := json.Unmarshal(req.ctx.Request.Body(), v)
	if error != nil {
		response := sunResponse{
			Msg:  "invalid json data",
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
