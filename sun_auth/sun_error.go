package sun_auth

import (
	"log"
)

type sunStatusCode uint8

const (
	SunOK sunStatusCode = iota
	SunBadRequest
	ServerError
)


func fatal(err error, msg string) {
	if err != nil {
		log.Fatalf("%s :: %v", msg, err)
	}
}
