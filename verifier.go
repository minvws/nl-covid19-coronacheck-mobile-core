package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	hcertverifier "github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	idemixverifier "github.com/minvws/nl-covid19-coronacheck-idemix/verifier"
	"os"
	"path"
	"time"
)

const (
	VERIFIER_CONFIG_FILENAME      = "config.json"
	VERIFIER_PUBLIC_KEYS_FILENAME = "public_keys.json"
)

const (
	VERIFICATION_SUCCESS = 1 + iota
	VERIFICATION_FAILED_UNRECOGNIZED_PREFIX
	VERIFICATION_FAILED_IS_NL_DCC
	VERIFICATION_FAILED_ERROR
)

type VerificationResult struct {
	Status  int
	Details *VerificationDetails
	Error   string
}

// VerificationDetails very much mimics the domestic verifier attributes, with only string type values,
//  to minimize app-side changes. In the future, both should return properly typed values.
type VerificationDetails struct {
	CredentialVersion string `json:"credentialVersion"`
	FirstNameInitial  string `json:"firstNameInitial"`
	LastNameInitial   string `json:"lastNameInitial"`
	BirthDay          string `json:"birthDay"`
	BirthMonth        string `json:"birthMonth"`

	IsSpecimen string `json:"isSpecimen"`
}

type verifierConfiguration struct {
	DomesticVerificationRules *domesticVerificationRules
	EuropeanVerificationRules *europeanVerificationRules
}

type domesticVerificationRules struct {
	QRValidForSeconds int `json:"qrValidForSeconds"`
}

type europeanVerificationRules struct {
	TestAllowedTypes  []string `json:"testAllowedTypes"`
	TestValidityHours int      `json:"testValidityHours"`

	VaccinationValidityDelayDays               int      `json:"vaccinationValidityDelayDays"`
	VaccinationJanssenValidityDelayDays        int      `json:"vaccinationJanssenValidityDelayDays"`
	VaccinationJanssenValidityIntoForceDateStr string   `json:"vaccinationJanssenValidityDelayIntoForceDate"`
	VaccineAllowedProducts                     []string `json:"vaccineAllowedProducts"`

	RecoveryValidFromDays  int `json:"recoveryValidFromDays"`
	RecoveryValidUntilDays int `json:"recoveryValidUntilDays"`

	vaccinationJanssenValidityDelayIntoForceDate time.Time
}

var (
	verifierConfig *verifierConfiguration

	domesticVerifier *idemixverifier.Verifier
	europeanVerifier *hcertverifier.Verifier
)

func InitializeVerifier(configDirectoryPath string) *Result {
	configPath := path.Join(configDirectoryPath, VERIFIER_CONFIG_FILENAME)
	pksPath := path.Join(configDirectoryPath, VERIFIER_PUBLIC_KEYS_FILENAME)

	// Load config
	configJson, err := os.ReadFile(configPath)
	if err != nil {
		return WrappedErrorResult(err, "Could not read verifier config file")
	}

	err = json.Unmarshal(configJson, &verifierConfig)
	if err != nil {
		return WrappedErrorResult(err, "Could not JSON unmarshal verifier config")
	}

	if verifierConfig.DomesticVerificationRules == nil {
		return ErrorResult(errors.Errorf("The domestic verification rules were not present"))
	}

	if verifierConfig.EuropeanVerificationRules == nil {
		return ErrorResult(errors.Errorf("The European verification rules were not present"))
	}

	// Parse date once (and leave at default value if parsing goes awry)
	verifierConfig.EuropeanVerificationRules.vaccinationJanssenValidityDelayIntoForceDate, _ = time.Parse(
		YYYYMMDD_FORMAT,
		verifierConfig.EuropeanVerificationRules.VaccinationJanssenValidityIntoForceDateStr,
	)

	// Read public keys
	publicKeysConfig, err := NewPublicKeysConfig(pksPath, true)
	if err != nil {
		return WrappedErrorResult(err, "Could not load public keys config")
	}

	// Initialize verifiers
	domesticVerifier = idemixverifier.New(publicKeysConfig.FindAndCacheDomestic)
	europeanVerifier = hcertverifier.New(publicKeysConfig.FindAndCacheEuropean)

	return &Result{nil, ""}
}

func Verify(proofQREncoded []byte) *VerificationResult {
	return verify(proofQREncoded, time.Now())
}

func verify(proofQREncoded []byte, now time.Time) *VerificationResult {
	if idemixverifier.HasNLPrefix(proofQREncoded) {
		return handleDomesticVerification(proofQREncoded, now)
	} else {
		return handleEuropeanVerification(proofQREncoded, now)
	}
}

func handleDomesticVerification(proofQREncoded []byte, now time.Time) *VerificationResult {
	verificationDetails, err := verifyDomestic(proofQREncoded, verifierConfig.DomesticVerificationRules, now)
	if err != nil {
		return &VerificationResult{
			Status: VERIFICATION_FAILED_ERROR,
			Error:  errors.WrapPrefix(err, "Could not verify domestic QR code", 0).Error(),
		}
	}

	return &VerificationResult{
		Status:  VERIFICATION_SUCCESS,
		Details: verificationDetails,
	}
}

func handleEuropeanVerification(proofQREncoded []byte, now time.Time) *VerificationResult {
	// As some QR-codes by T-Systems apps miss the required prefix, add the prefix here if it isn't present
	wasEUPrefixed := hcertcommon.HasEUPrefix(proofQREncoded)
	if !wasEUPrefixed {
		proofQREncoded = append([]byte{'H', 'C', '1', ':'}, proofQREncoded...)
	}

	verificationDetails, isNLDCC, err := verifyEuropean(proofQREncoded, verifierConfig.EuropeanVerificationRules, now)
	if err != nil {
		// If the QR-code wasn't prefixed and it didn't verify, assume that it wasn't a EU QR code
		if !wasEUPrefixed {
			return &VerificationResult{
				Status: VERIFICATION_FAILED_UNRECOGNIZED_PREFIX,
			}
		}

		return &VerificationResult{
			Status: VERIFICATION_FAILED_ERROR,
			Error:  errors.WrapPrefix(err, "Could not verify european QR code", 0).Error(),
		}
	}

	if isNLDCC {
		return &VerificationResult{
			Status: VERIFICATION_FAILED_IS_NL_DCC,
		}
	}

	return &VerificationResult{
		Status:  VERIFICATION_SUCCESS,
		Details: verificationDetails,
	}
}
