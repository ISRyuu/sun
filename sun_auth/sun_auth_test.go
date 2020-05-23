package sun_auth

import (
	"testing"
)

func TestRandomPassword(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Log(RandomPassword(i))
	}
}
