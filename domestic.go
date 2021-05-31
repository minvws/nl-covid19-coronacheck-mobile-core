package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/minvws/nl-covid19-coronacheck-idemix/holder"
	"github.com/minvws/nl-covid19-coronacheck-idemix/verifier"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"strconv"
)

type AnnotatedPk struct {
	Id    string `json:"id"`
	PkXml []byte `json:"public_key"`
}

type createCredentialResultValue struct {
	Credential *gabi.Credential  `json:"credential"`
	Attributes map[string]string `json:"attributes"`
}

var loadedIssuerPks map[string]*gabi.PublicKey
var HasLoadedDomesticIssuerPks bool = false

func LoadDomesticIssuerPks(annotatedPksJson []byte) *Result {
	// Unmarshal JSON list of keys
	annotatedPks := make([]AnnotatedPk, 0)
	err := json.Unmarshal(annotatedPksJson, &annotatedPks)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not unmarshal annotated issuer public keys", 0))
	}

	// Unmarshal base64 XML-encoded keys
	// Allow unmarshalling errors to allow for forward-compatibility
	pks := map[string]*gabi.PublicKey{}
	for _, annotatedPk := range annotatedPks {
		pk, err := gabi.NewPublicKeyFromXML(string(annotatedPk.PkXml))
		if err != nil {
			continue
		}

		pks[annotatedPk.Id] = pk
	}

	if len(pks) == 0 {
		return errorResult(errors.Errorf("No valid public keys were supplied"))
	}

	loadedIssuerPks = pks
	HasLoadedDomesticIssuerPks = true

	return &Result{nil, ""}
}

func GenerateHolderSk() *Result {
	holderSkJson, err := json.Marshal(holder.GenerateSk())
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not serialize holder secret key", 0))
	}

	return &Result{holderSkJson, ""}
}

var lastCredBuilders []gabi.ProofBuilder

func CreateCommitmentMessage(holderSkJson, prepareIssueMessageJson []byte) *Result {
	holderSk, err := unmarshalHolderSk(holderSkJson)
	if err != nil {
		return errorResult(err)
	}

	pim := &common.PrepareIssueMessage{}
	err = json.Unmarshal(prepareIssueMessageJson, pim)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not JSON unmarshal prepare issue message", 0))
	}

	h := holder.New(holderSk, loadedIssuerPks)

	var icm *gabi.IssueCommitmentMessage
	lastCredBuilders, icm, err = h.CreateCommitments(pim)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not create commitments", 0))
	}

	icmJson, err := json.Marshal(icm)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not marshal issue commitment message", 0))
	}

	return &Result{icmJson, ""}
}

func CreateCredentials(ccmsJson []byte) *Result {
	credBuilders := lastCredBuilders
	lastCredBuilders = nil

	if credBuilders == nil {
		return errorResult(errors.Errorf("CreateCommitmentMessage should be called before CreateCredentials"))
	}

	var ccms []*common.CreateCredentialMessage
	err := json.Unmarshal(ccmsJson, &ccms)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not unmarshal create credential messages", 0))
	}

	// TODO: Refactor holder struct so that nil doesn't have to be passed here
	h := holder.New(nil, loadedIssuerPks)

	creds, err := h.CreateCredentials(credBuilders, ccms)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not create credentials", 0))
	}

	results := make([]*createCredentialResultValue, 0, len(creds))
	for _, cred := range creds {
		attributes, err := readCredentialWithVersion(cred)
		if err != nil {
			return errorResult(err)
		}

		result := &createCredentialResultValue{
			Credential: cred,
			Attributes: attributes,
		}

		results = append(results, result)
	}

	resultsJson, err := json.Marshal(results)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not marshal read credential result", 0))
	}

	return &Result{resultsJson, ""}
}

func ReadDomesticCredential(credJson []byte) *Result {
	cred, err := unmarshalCredential(credJson)
	if err != nil {
		return errorResult(err)
	}

	attributes, err := readCredentialWithVersion(cred)
	if err != nil {
		return errorResult(err)
	}

	attributesJson, err := json.Marshal(attributes)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could marshal attributes", 0))
	}

	return &Result{attributesJson, ""}
}

func Disclose(holderSkJson, credJson []byte) *Result {
	holderSk, err := unmarshalHolderSk(holderSkJson)
	if err != nil {
		return errorResult(err)
	}

	cred, err := unmarshalCredential(credJson)
	if err != nil {
		return errorResult(err)
	}

	h := holder.New(holderSk, loadedIssuerPks)
	proofBase45, err := h.DiscloseAllWithTimeQREncoded(cred)
	if err != nil {
		return errorResult(errors.WrapPrefix(err, "Could not disclosure credential", 0))
	}

	return &Result{proofBase45, ""}
}

// TODO: Add checking of verified time 'challenge'
func verifyDomestic(proofBase45 []byte) (attributes map[string]string, err error) {
	v := verifier.New(loadedIssuerPks)

	verifiedCred, err := v.VerifyQREncoded(proofBase45)
	if err != nil {
		return nil, err
	}

	attributes = verifiedCred.Attributes
	attributes["credentialVersion"] = strconv.Itoa(verifiedCred.CredentialVersion)

	return attributes, nil
}

func unmarshalHolderSk(holderSkJson []byte) (*big.Int, error) {
	holderSk := new(big.Int)
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0)
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

	// Add the credential version to the attributes
	attributes["credentialVersion"] = strconv.Itoa(credVersion)

	return attributes, nil
}
