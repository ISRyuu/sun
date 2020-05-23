package sun_auth

import (
	"bytes"
	"math/rand"
	"time"

	uuid "github.com/satori/go.uuid"
)

const randomCharSet = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789"

func RandomPassword(length int) string {
	var b bytes.Buffer
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < length; i++ {
		b.WriteByte(randomCharSet[rand.Intn(len(randomCharSet))])
	}
	return b.String()
}

func GenUUID() string {
	return uuid.NewV4().String()
}
