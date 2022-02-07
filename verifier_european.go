package mobilecore

import (
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	"regexp"
	"strings"
	"time"
)

const (
	HCERT_SPECIMEN_EXPIRATION_TIME    int64 = 42
	DISEASE_TARGETED_COVID_19               = "840539006"
	TEST_RESULT_NOT_DETECTED                = "260415000"
	VACCINE_MEDICINAL_PRODUCT_JANSSEN       = "EU/1/20/1525"

	YYYYMMDD_FORMAT = "2006-01-02"
	DOB_EMPTY_VALUE = "XX"
)

var (
	DATE_OF_BIRTH_REGEX = regexp.MustCompile(`^(?:((?:19|20)\d\d)(?:-(\d\d)(?:-(\d\d))?)?)?$`)
)

func verifyEuropean(proofQREncoded []byte, policy string, rules *europeanVerificationRules, now time.Time) (details *VerificationDetails, isNLDCC bool, err error) {
	// Validate signature and get health certificate
	verified, err := europeanVerifier.VerifyQREncoded(proofQREncoded)
	if err != nil {
		return nil, false, err
	}

	hcert := verified.HealthCertificate
	pk := verified.PublicKey

	// Check denylist
	err = checkDenylist(verified.ProofIdentifier, rules.ProofIdentifierDenylist)
	if err != nil {
		return nil, false, err
	}

	// Exit early if it's an NL-issued CWT, so domestic credentials must be used instead
	// As the constituent countries don't have domestic credentials, check if the subject alternative name
	//  of the public key is present and NLD. In that case European credentials are allowed.
	if hcert.Issuer == "NL" && (len(pk.SubjectAltName) != 3 || pk.SubjectAltName == "NLD") {
		return nil, true, nil
	}

	// Validate health certificate metadata, and see if it's a specimen certificate
	isSpecimen, err := validateHcert(hcert, now)
	if err != nil {
		return nil, false, errors.WrapPrefix(err, "Could not validate health certificate", 0)
	}

	// Validate DCC
	err = validateDCC(hcert.DCC, policy, rules, now)
	if err != nil {
		return nil, false, errors.WrapPrefix(err, "Could not validate DCC", 0)
	}

	// Build the resulting details
	result, err := buildVerificationDetails(hcert, pk, rules, isSpecimen)
	if err != nil {
		return nil, false, err
	}

	return result, false, nil
}

func validateHcert(hcert *hcertcommon.HealthCertificate, now time.Time) (isSpecimen bool, err error) {
	// Check for a 'magic' expirationTime value, to determine if it's a specimen certificate
	if hcert.ExpirationTime == HCERT_SPECIMEN_EXPIRATION_TIME {
		return true, nil
	}

	// Check for invalid cases of issuedAt and expirationTime
	issuedAt := time.Unix(hcert.IssuedAt, 0)
	expirationTime := time.Unix(hcert.ExpirationTime, 0)

	if expirationTime.Before(issuedAt) {
		return false, errors.Errorf("Cannot be issued after it expires")
	}

	if now.Before(issuedAt) {
		return false, errors.Errorf("Is issued before the current time")
	}

	if expirationTime.Before(now) {
		return false, errors.Errorf("Is not valid anymore; was valid until %d", hcert.ExpirationTime)
	}

	return false, nil
}

func validateDCC(dcc *hcertcommon.DCC, policy string, rules *europeanVerificationRules, now time.Time) (err error) {
	// Validate date of birth
	err = validateDateOfBirth(dcc.DateOfBirth)
	if err != nil {
		return errors.WrapPrefix(err, "Invalid date of birth", 0)
	}

	// Validate name
	err = validateName(dcc.Name)
	if err != nil {
		return errors.WrapPrefix(err, "Invalid name", 0)
	}

	// Validate statement amount
	err = validateStatementAmount(dcc)
	if err != nil {
		return errors.WrapPrefix(err, "Invalid statement amount", 0)
	}

	// Validate statements
	for _, vacc := range dcc.Vaccinations {
		err = validateVaccination(vacc, dcc.DateOfBirth, policy, rules, now)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid vaccination statement", 0)
		}
	}

	for _, test := range dcc.Tests {
		err = validateTest(test, rules, now)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid test statement", 0)
		}
	}

	for _, rec := range dcc.Recoveries {
		err = validateRecovery(rec, policy, rules, now)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid recovery statement", 0)
		}
	}

	return nil
}

func validateDateOfBirth(dob string) error {
	_, _, _, err := parseDateOfBirth(dob)
	if err != nil {
		return errors.WrapPrefix(err, "Invalid date of birth", 0)
	}

	return nil
}

func validateName(name *hcertcommon.DCCName) error {
	if name.StandardizedFamilyName == "" && name.StandardizedGivenName == "" {
		return errors.Errorf("Either the standardized family name or given name must be present")
	}

	return nil
}

func validateStatementAmount(dcc *hcertcommon.DCC) error {
	vaccAmount := len(dcc.Vaccinations)
	testAmount := len(dcc.Tests)
	recAmount := len(dcc.Recoveries)
	totalAmount := vaccAmount + testAmount + recAmount

	if totalAmount == 0 {
		return errors.Errorf("Contains no vaccination, test or recovery statements")
	}

	if totalAmount > 1 {
		return errors.Errorf(
			"Contains too many statements (%d vaccinations, %d tests and %d recoveries)",
			vaccAmount, testAmount, recAmount,
		)
	}

	return nil
}

func validateVaccination(vacc *hcertcommon.DCCVaccination, dob string, policy string, rules *europeanVerificationRules, now time.Time) error {
	// 1G policy doesn't allow vaccinations
	if policy == VERIFICATION_POLICY_1G {
		return errors.Errorf("A vaccination is not valid for the chosen 1G policy")
	}

	// Disease agent
	if !trimmedStringEquals(vacc.DiseaseTargeted, DISEASE_TARGETED_COVID_19) {
		return errors.Errorf("Disease targeted should be COVID-19")
	}

	// Allowed vaccine
	if !containsTrimmedString(rules.VaccineAllowedProducts, vacc.MedicinalProduct) {
		return errors.Errorf("Medicinal product is not accepted")
	}

	// Dose number and total number of doses
	if vacc.DoseNumber < vacc.TotalSeriesOfDoses {
		return errors.Errorf("Dose number is smaller than the specified total amount of doses")
	}

	// Date of vaccination with a configured delay in validity, with a special case for Janssen and boosters
	dov, err := parseDate(vacc.DateOfVaccination)
	if err != nil {
		return errors.Errorf("Date of vaccination could not be parsed")
	}

	// Determine waiting days depending on vaccine type and dose number
	validityDelayDays := rules.VaccinationValidityDelayDays
	if trimmedStringEquals(vacc.MedicinalProduct, VACCINE_MEDICINAL_PRODUCT_JANSSEN) {
		validityDelayDays = rules.VaccinationJanssenValidityDelayDays
		if vacc.DoseNumber > 1 {
			validityDelayDays = 0
		}
	} else {
		if vacc.DoseNumber > 2 {
			validityDelayDays = 0
		}
	}

	// Check if the dosenumber and the total amount of doses explicitly denote a booster
	if vacc.DoseNumber > vacc.TotalSeriesOfDoses {
		validityDelayDays = 0
	}

	// Apply waiting days and check if the vaccination validity period has started
	validFrom := dov.Add(time.Duration(validityDelayDays*24) * time.Hour)
	if now.Before(validFrom) {
		return errors.Errorf("Date of vaccination is before the delayed validity date")
	}

	// From the into force date from a minimum age (typically adults),
	//  check if the vaccination validity has not yet ended
	dobTime, err := mostRecentDOBDayMonth(dob)
	if err != nil {
		return errors.WrapPrefix(err, "Could not determine most recent date of birth day/month", 0)
	}

	isAdult := dobTime.AddDate(rules.VaccinationMinimumAgeForValidityYears, 0, 0).Before(now)
	if rules.vaccinationValidityIntoForceDate.Before(now) && isAdult {
		validUntil := dov.Add(time.Duration(rules.VaccinationValidityDays*24) * time.Hour)
		if validUntil.Before(now) {
			return errors.Errorf("Date of vaccination is beyond the primary cycle validity period")
		}
	}

	return nil
}

func validateTest(test *hcertcommon.DCCTest, rules *europeanVerificationRules, now time.Time) error {
	// Disease agent
	if !trimmedStringEquals(test.DiseaseTargeted, DISEASE_TARGETED_COVID_19) {
		return errors.Errorf("Disease targeted should be COVID-19")
	}

	// Test type
	// The current business rules don't specify that we check for specific ma values
	if !containsTrimmedString(rules.TestAllowedTypes, test.TypeOfTest) {
		return errors.Errorf("Type is not allowed")
	}

	// Test result
	if !trimmedStringEquals(test.TestResult, TEST_RESULT_NOT_DETECTED) {
		return errors.Errorf("Result should be negative (not detected)")
	}

	// Test time of collection
	doc, err := time.Parse(time.RFC3339, test.DateTimeOfCollection)
	if err != nil {
		return errors.Errorf("Time of collection could not be parsed")
	}

	testValidityHours := rules.TestValidityHours
	testValidityDuration := time.Duration(testValidityHours) * time.Hour

	testExpirationTime := doc.Add(testValidityDuration)
	if testExpirationTime.Before(now) {
		return errors.Errorf("Time of collection is more than %s ago", testValidityDuration.String())
	}

	if now.Before(doc) {
		return errors.Errorf("Time of collection is in the future")
	}

	return nil
}

func validateRecovery(rec *hcertcommon.DCCRecovery, policy string, rules *europeanVerificationRules, now time.Time) error {
	// 1G policy doesn't allow vaccinations
	if policy == VERIFICATION_POLICY_1G {
		return errors.Errorf("A recovery is not valid for the chosen 1G policy")
	}

	// Disease agent
	if !trimmedStringEquals(rec.DiseaseTargeted, DISEASE_TARGETED_COVID_19) {
		return errors.Errorf("Disease targeted should be COVID-19")
	}

	testDate, err := parseDate(rec.DateOfFirstPositiveTest)
	if err != nil {
		return errors.Errorf("Date of first positive test could not be parsed")
	}

	// Validity
	// First calculate the validity according to our own rules
	validFromDays := rules.RecoveryValidFromDays
	validUntilDays := rules.RecoveryValidUntilDays

	validFrom := testDate.Add(time.Duration(validFromDays*24) * time.Hour)
	validUntil := testDate.Add(time.Duration(validUntilDays*24) * time.Hour)

	// If the specified validity is smaller on any side, use that specified validity
	specifiedValidFrom, err := parseDate(rec.CertificateValidFrom)
	if err == nil && specifiedValidFrom.After(validFrom) {
		validFrom = specifiedValidFrom
	}

	specifiedValidUntil, err := parseDate(rec.CertificateValidUntil)
	if err == nil && specifiedValidUntil.Before(validUntil) {
		validUntil = specifiedValidUntil
	}

	// Actually validate
	if validUntil.Before(validFrom) {
		return errors.Errorf("Valid until cannot be before valid from")
	}

	if now.Before(validFrom) {
		return errors.Errorf("Recovery is not yet valid")
	}

	if validUntil.Before(now) {
		return errors.Errorf("Recovery is not valid anymore")
	}

	return nil
}

func buildVerificationDetails(hcert *hcertcommon.HealthCertificate, pk *verifier.AnnotatedEuropeanPk, rules *europeanVerificationRules, isSpecimen bool) (*VerificationDetails, error) {
	// Determine specimen
	isSpecimenStr := "0"
	if isSpecimen {
		isSpecimenStr = "1"
	}

	// Normalize date of birth
	_, birthMonth, birthDay, err := parseDateOfBirth(hcert.DCC.DateOfBirth)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not parse date of birth", 0)
	}

	if birthMonth == "" {
		birthMonth = DOB_EMPTY_VALUE
	}

	if birthDay == "" {
		birthDay = DOB_EMPTY_VALUE
	}

	// Get first character of name(s)
	firstNameInitial := ""
	if len(hcert.DCC.Name.StandardizedGivenName) > 0 {
		firstNameInitial = hcert.DCC.Name.StandardizedGivenName[0:1]
	}

	familyNameInitial := ""
	if len(hcert.DCC.Name.StandardizedFamilyName) > 0 {
		familyNameInitial = hcert.DCC.Name.StandardizedFamilyName[0:1]
	}

	// Add the issuing country according to the hcert issuer field
	// For the NL-issuer, determine the two-letter country code from the public key SAN
	issCountryCode := hcert.Issuer
	if issCountryCode == "NL" {
		pkCountryCode, ok := rules.IssuerCountryCodeFromCASIslandSAN[pk.SubjectAltName]
		if ok {
			issCountryCode = pkCountryCode
		}
	}

	// Correct the issuer country code for some countries not adhering to the spec
	correctedCountryCode, ok := rules.CorrectedIssuerCountryCodes[issCountryCode]
	if ok {
		issCountryCode = correctedCountryCode
	}

	return &VerificationDetails{
		CredentialVersion: "1",
		IsSpecimen:        isSpecimenStr,
		IssuerCountryCode: issCountryCode,

		BirthMonth:       birthMonth,
		BirthDay:         birthDay,
		FirstNameInitial: firstNameInitial,
		LastNameInitial:  familyNameInitial,
	}, nil
}

// To handle the special case of BG/GR including spaces in certain values,
//   all string values are trimmed before doing a equality check
func trimmedStringEquals(untrimmed, compareTo string) bool {
	trimmed := strings.TrimSpace(untrimmed)
	return trimmed == compareTo
}

// Same as with trimmedStringEquals
func containsTrimmedString(list []string, untrimmed string) bool {
	trimmed := strings.TrimSpace(untrimmed)
	for _, elem := range list {
		if elem == trimmed {
			return true
		}
	}

	return false
}
