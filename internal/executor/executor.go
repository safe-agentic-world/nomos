package executor

import "errors"

var ErrNotImplemented = errors.New("executor not implemented")

type Executor interface {
	Execute() error
}
