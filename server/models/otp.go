package models

import (
	"time"

	"github.com/sdsProject/server/salt"
)

type Otp struct {
	Pin  string
	Time int64
}

//GenerateOTP constructor
func GenerateOTP() Otp {
	return Otp{salt.RandStringBytesMask(5), now()}
}

//ValidateOTP valida el pin introducido en función del tiempo limite introducido
func ValidateOTP(pin string, otp Otp, time int64) bool {
	if pin != otp.Pin || (otp.Time+time)-now() < 0 {
		return false
	}
	return true
}

func now() int64 {
	return time.Now().UTC().Unix()
}
