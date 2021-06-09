package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	idemixcommon "github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/minvws/nl-covid19-coronacheck-idemix/holder"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"strconv"
	"time"
)

type CreateCredentialResultValue struct {
	Credential *gabi.Credential  `json:"credential"`
	Attributes map[string]string `json:"attributes"`
}

func GenerateHolderSk() *Result {
	holderSkJson, err := json.Marshal(holder.GenerateSk())
	if err != nil {
		return WrappedErrorResult(err, "Could not serialize holdercore secret key")
	}

	return &Result{holderSkJson, ""}
}

func CreateCommitmentMessage(holderSkJson, prepareIssueMessageJson []byte) *Result {
	holderSk, err := unmarshalHolderSk(holderSkJson)
	if err != nil {
		return ErrorResult(err)
	}

	pim := &idemixcommon.PrepareIssueMessage{}
	err = json.Unmarshal(prepareIssueMessageJson, pim)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON unmarshal prepare issue message")
	}

	var icm *gabi.IssueCommitmentMessage
	lastCredBuilders, icm, err = domesticHolder.CreateCommitments(holderSk, pim)
	if err != nil {
		return WrappedErrorResult(err, "Could not create commitments")
	}

	icmJson, err := json.Marshal(icm)
	if err != nil {
		return WrappedErrorResult(err, "Could not marshal issue commitment message")
	}

	return &Result{icmJson, ""}
}

func CreateCredentials(ccmsJson []byte) *Result {
	credBuilders := lastCredBuilders
	lastCredBuilders = nil

	if credBuilders == nil {
		return ErrorResult(errors.Errorf("CreateCommitmentMessage should be called before CreateCredentials"))
	}

	var ccms []*idemixcommon.CreateCredentialMessage
	err := json.Unmarshal(ccmsJson, &ccms)
	if err != nil {
		return WrappedErrorResult(err, "Could not unmarshal create credential messages")
	}

	creds, err := domesticHolder.CreateCredentials(credBuilders, ccms)
	if err != nil {
		return WrappedErrorResult(err, "Could not create credentials")
	}

	results := make([]*CreateCredentialResultValue, 0, len(creds))
	for _, cred := range creds {
		attributes, err := readCredentialWithVersion(cred)
		if err != nil {
			return ErrorResult(err)
		}

		result := &CreateCredentialResultValue{
			Credential: cred,
			Attributes: attributes,
		}

		results = append(results, result)
	}

	resultsJson, err := json.Marshal(results)
	if err != nil {
		return WrappedErrorResult(err, "Could not marshal read credential result")
	}

	return &Result{resultsJson, ""}
}

func ReadDomesticCredential(credJson []byte) *Result {
	cred, err := unmarshalCredential(credJson)
	if err != nil {
		return ErrorResult(err)
	}

	attributes, err := readCredentialWithVersion(cred)
	if err != nil {
		return ErrorResult(err)
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return WrappedErrorResult(err, "Could marshal attributes")
	}

	return &Result{attributesJson, ""}
}

func Disclose(holderSkJson, credJson []byte) *Result {
	return disclose(holderSkJson, credJson, time.Now())
}

func disclose(holderSkJson, credJson []byte, now time.Time) *Result {
	holderSk, err := unmarshalHolderSk(holderSkJson)
	if err != nil {
		return ErrorResult(err)
	}

	cred, err := unmarshalCredential(credJson)
	if err != nil {
		return ErrorResult(err)
	}

	proofBase45, err := domesticHolder.DiscloseAllWithTimeQREncoded(holderSk, cred, now)
	if err != nil {
		return WrappedErrorResult(err, "Could not disclosure credential")
	}

	return &Result{proofBase45, ""}
}

func unmarshalHolderSk(holderSkJson []byte) (*big.Int, error) {
	holderSk := new(big.Int)
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal holdercore sk", 0)
	}

	return holderSk, nil
}

func unmarshalCredential(credJson []byte) (*gabi.Credential, error) {
	cred := new(gabi.Credential)
	err := json.Unmarshal(credJson, cred)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal credential", 0)
	}

	return cred, nil
}

func readCredentialWithVersion(cred *gabi.Credential) (map[string]string, error) {
	attributes, credVersion, err := holder.ReadCredential(cred)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not read credential", 0)
	}

	// For v1 compatibility, add v2 and remove v1 attributes
	if credVersion == 1 {
		attributes["stripType"] = attributes["isPaperProof"]
		attributes["validFrom"] = attributes["sampleTime"]
		attributes["validForHours"] = V1_VALIDITY_HOURS_STR

		delete(attributes, "isPaperProof")
		delete(attributes, "testType")
		delete(attributes, "sampleTime")
	}

	// Add the credential version to the attributes
	attributes["credentialVersion"] = strconv.Itoa(credVersion)

	return attributes, nil
}
