package utils

import (
	"math/rand"
	"strings"
	"time"
)

// from https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIndexBits = 6
	letterIndexMask = 1<<letterIndexBits - 1
	letterIndexMax  = 63 / letterIndexBits
)

var src = rand.NewSource(time.Now().UnixNano())

func GenerateRandomString(n int) string {
	s := strings.Builder{}
	s.Grow(n)
	for i, c, r := n-1, src.Int63(), letterIndexMax; i >= 0; {
		if r == 0 {
			c, r = src.Int63(), letterIndexMax
		}
		if idx := int(c & letterIndexMask); idx < len(letters) {
			s.WriteByte(letters[idx])
			i--
		}
		c >>= letterIndexBits
		r--
	}
	return s.String()
}
