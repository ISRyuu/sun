package sun_auth

type sunStatusCode uint8

const (
	SunOK sunStatusCode = iota
	SunBadRequest
	ServerError
)
