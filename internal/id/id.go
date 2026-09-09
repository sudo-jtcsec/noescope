package id

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

func New(prefix string) string {
	value := ulid.MustNew(
		ulid.Timestamp(time.Now()),
		rand.Reader,
	)

	if prefix == "" {
		return value.String()
	}

	return prefix + "_" + value.String()
}
