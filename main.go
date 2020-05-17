package main

import (
	"sun/sun_auth"
)

func main() {
	sun_auth.NewSunJwt().Forever(":9900")
}
