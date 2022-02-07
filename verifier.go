package mobilecore

import (
	"encoding/base64"
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

const (
	VERIFICATION_POLICY_1G string = "1"
	VERIFICATION_POLICY_3G string = "3"
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
	IsSpecimen        string `json:"isSpecimen"`
	IssuerCountryCode string `json:"issuerCountryCode"`

	FirstNameInitial string `json:"firstNameInitial"`
	LastNameInitial  string `json:"lastNameInitial"`
	BirthDay         string `json:"birthDay"`
	BirthMonth       string `json:"birthMonth"`
}

type verifierConfiguration struct {
	DomesticVerificationRules *domesticVerificationRules
	EuropeanVerificationRules *europeanVerificationRules
}

type domesticVerificationRules struct {
	QRValidForSeconds       int             `json:"qrValidForSeconds"`
	ProofIdentifierDenylist map[string]bool `json:"proofIdentifierDenylist"`
}

type europeanVerificationRules struct {
	TestAllowedTypes  []string `json:"testAllowedTypes"`
	TestValidityHours int      `json:"testValidityHours"`

	VaccinationValidityDelayDays          int      `json:"vaccinationValidityDelayDays"`
	VaccinationJanssenValidityDelayDays   int      `json:"vaccinationJanssenValidityDelayDays"`
	VaccinationValidityDays               int      `json:"vaccinationValidityDays"`
	VaccinationValidityIntoForceDateStr   string   `json:"vaccinationValidityIntoForceDate"`
	VaccinationMinimumAgeForValidityYears int      `json:"vaccinationMinimumAgeForValidityYears"`
	VaccineAllowedProducts                []string `json:"vaccineAllowedProducts"`

	RecoveryValidFromDays  int `json:"recoveryValidFromDays"`
	RecoveryValidUntilDays int `json:"recoveryValidUntilDays"`

	IssuerCountryCodeFromCASIslandSAN map[string]string `json:"issuerCountryCodeFromCASIslandSAN"`
	CorrectedIssuerCountryCodes       map[string]string `json:"correctedIssuerCountryCodes"`

	ProofIdentifierDenylist map[string]bool `json:"proofIdentifierDenylist"`

	vaccinationValidityIntoForceDate time.Time
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
	verifierConfig.EuropeanVerificationRules.vaccinationValidityIntoForceDate, _ = time.Parse(
		YYYYMMDD_FORMAT,
		verifierConfig.EuropeanVerificationRules.VaccinationValidityIntoForceDateStr,
	)

	// Read public keys
	publicKeysConfig, err := NewPublicKeysConfig(pksPath, true)
	if err != nil {
		return WrappedErrorResult(err, "Could not load public keys config")
	}

	// Initialize verifiers
	domesticVerifier = idemixverifier.New(publicKeysConfig.FindAndCacheDomestic)
	europeanVerifier = hcertverifier.New(publicKeysConfig.EuropeanPks)

	return &Result{nil, ""}
}

func Verify(proofQREncoded []byte, verificationPolicy string) *VerificationResult {
	return verify(proofQREncoded, verificationPolicy, time.Now())
}

func VerifyWithTime(proofQREncoded []byte, verificationPolicy string, unixTimeSeconds int64) *VerificationResult {
	return verify(proofQREncoded, verificationPolicy, time.Unix(unixTimeSeconds, 0))
}

func verify(proofQREncoded []byte, policy string, now time.Time) *VerificationResult {
	// Verification policy must be either 1G or 3G
	if policy != VERIFICATION_POLICY_1G && policy != VERIFICATION_POLICY_3G {
		return &VerificationResult{
			Status: VERIFICATION_FAILED_ERROR,
			Error:  errors.Errorf("Unrecognized policy was provided").Error(),
		}
	}

	if idemixverifier.HasNLPrefix(proofQREncoded) {
		return handleDomesticVerification(proofQREncoded, policy, now)
	} else {
		return handleEuropeanVerification(proofQREncoded, policy, now)
	}
}

func handleDomesticVerification(proofQREncoded []byte, policy string, now time.Time) *VerificationResult {
	rules := verifierConfig.DomesticVerificationRules
	verificationDetails, err := verifyDomestic(proofQREncoded, policy, rules, now)
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

func handleEuropeanVerification(proofQREncoded []byte, policy string, now time.Time) *VerificationResult {
	// As some QR-codes by T-Systems apps miss the required prefix, add the prefix here if it isn't present
	wasEUPrefixed := hcertcommon.HasEUPrefix(proofQREncoded)
	if !wasEUPrefixed {
		proofQREncoded = append([]byte{'H', 'C', '1', ':'}, proofQREncoded...)
	}

	rules := verifierConfig.EuropeanVerificationRules
	verificationDetails, isNLDCC, err := verifyEuropean(proofQREncoded, policy, rules, now)
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

func checkDenylist(proofIdentifier []byte, denyList map[string]bool) error {
	proofIdentifierBase64 := base64.StdEncoding.EncodeToString(proofIdentifier)

	denied, ok := denyList[proofIdentifierBase64]
	if ok && denied {
		return errors.Errorf("The credential identifier was present in the proof identifier denylist")
	}

	return nil
}

func GetVerifiersForCLI() (*idemixverifier.Verifier, *hcertverifier.Verifier) {
	return domesticVerifier, europeanVerifier
}
