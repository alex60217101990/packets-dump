package errors

import (
	"errors"
)

var (
	ErrInvalidL4ProtoType = errors.New("invalid protocol types parameter")
)