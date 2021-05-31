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

// Stubs
type VerifyResult struct {
	AttributesJson  []byte
	UnixTimeSeconds int64
	Error           string
}

func VerifyQREncoded(proofQrEncodedAsn1 []byte) *VerifyResult {
	// not implemented
	return &VerifyResult{[]byte{}, 0, ""}
}
