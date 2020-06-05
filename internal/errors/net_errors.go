package errors

import (
	"errors"
)

var (
	BadFileDescriptor = errors.New("bad file descriptor")
)
