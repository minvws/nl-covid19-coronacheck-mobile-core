package mobilecore

import "github.com/go-errors/errors"

type Result struct {
	Value []byte
	Error string
}

func WrappedErrorResult(err error, prefix string) *Result {
	if err == nil {
		panic("Assertion failed: error should not be nil")
	}

	return ErrorResult(errors.WrapPrefix(err, prefix, 1))
}

func ErrorResult(err error) *Result {
	if err == nil {
		panic("Assertion failed: error should not be nil")
	}

	return &Result{nil, err.Error()}
}
