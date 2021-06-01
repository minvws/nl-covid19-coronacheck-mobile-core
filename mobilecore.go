package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"unicode"
)

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

func InitializeVerifier(configDirectoryPath string) {
	// FIXME: Not implemented
}

func Verify(proofQREncoded []byte) *Result {
	var attributes map[string]string
	var err error

	if hcertcommon.HasEUPrefix(proofQREncoded) {
		attributes, err = verifyEuropean(proofQREncoded)
		if err != nil {
			return errorResult(errors.WrapPrefix(err, "Could not verify European credential", 0))
		}
	} else {
		attributes, err = verifyDomestic(proofQREncoded)
		if err != nil {
			return errorResult(errors.WrapPrefix(err, "Could not verify domestic credential", 0))
		}
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not JSON marshal verified attributes", 0))
	}

	return &Result{attributesJson, ""}
}

// Doesn't do prefixes like 't, and 's- yet
func normalizeName(input string) (string, error) {
	rf := transform.RemoveFunc(func(r rune) bool {
		return unicode.Is(unicode.Mn, r) && !unicode.Is(unicode.Punct, r)
	})

	t := transform.Chain(norm.NFD, rf, norm.NFC)
	normalized, _, err := transform.String(t, input)
	if err != nil {
		return "", errors.WrapPrefix(err, "Could not normalize name", 0)
	}

	if len(normalized) == 0 {
		return "", errors.Errorf("Normalization result is empty")
	}

	return normalized, err
}

// Temporary mocks for compatibility reasons while the app is being rewritten
type VerifyResult struct {
	AttributesJson  []byte
	UnixTimeSeconds int64
	Error           string
}

func VerifyQREncoded(proofQrEncodedAsn1 []byte) *VerifyResult {
	return &VerifyResult{[]byte{}, 0, ""}
}