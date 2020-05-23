package sun_auth

import (
	"log"
)

type sunStatusCode uint8

const (
	SunOK sunStatusCode = iota
	SunBadRequest
	ServerError
	BadRequest
)

func fatal(err error, msg string) {
	if err != nil {
		log.Fatalf("%s :: %v", msg, err)
	}
}
