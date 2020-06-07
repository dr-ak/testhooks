package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

func IsValidPayload(secret, headerHash string, payload []byte) bool {
	hash := "sha1=" + HashPayload(secret, payload)
	return hmac.Equal(
		[]byte(hash),
		[]byte(headerHash),
	)
}

func HashPayload(secret string, playloadBody []byte) string {
	hm := hmac.New(sha1.New, []byte(secret))
	hm.Write(playloadBody)
	sum := hm.Sum(nil)
	return fmt.Sprintf("%x", sum)
}
