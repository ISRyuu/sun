package sun_auth

type sunStatusCode uint8

type sunResponse struct {
	Msg  string        `json:"msg"`
	Code sunStatusCode `json:"code"`
	Data interface{}   `json:"data,omitempty"`
}

const (
	SunOK sunStatusCode = iota
	SunBadRequest
	ServerError
)
