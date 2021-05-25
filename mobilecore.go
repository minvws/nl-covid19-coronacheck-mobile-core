package mobilecore

type Result struct {
	Value []byte
	Error string
}

func errorResult(err error) *Result {
	if err == nil {
		panic("Assertion failed: error should not be nil")
	}

	return &Result{nil, err.Error()}
}