package mobilecore

import (
	"github.com/go-errors/errors"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"regexp"
	"time"
)

const (
	HCERT_SPECIMEN_EXPIRATION_TIME int64 = 42
	DISEASE_TARGETED_COVID_19            = "840539006"
	TEST_RESULT_NOT_DETECTED             = "260415000"

	YYYYMMDD_FORMAT = "2006-01-02"
	DOB_EMPTY_VALUE = "XX"
)

func verifyEuropean(proofQREncoded []byte, now time.Time) (*VerificationResult, error) {
	// Validate signature and get health certificate
	hcert, err := europeanVerifier.VerifyQREncoded(proofQREncoded)
	if err != nil {
		return nil, err
	}

	// Validate health certificate metadata, and see if it's a specimen certificate
	isSpecimen, err := validateHcert(hcert, now)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not validate health certificate", 0)
	}

	err = validateDCC(hcert.DCC, now)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not validate DCC", 0)
	}

	result, err := buildVerificationResult(hcert, isSpecimen)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func validateHcert(hcert *hcertcommon.HealthCertificate, now time.Time) (isSpecimen bool, err error) {
	if hcert.IssuedAt > hcert.ExpirationTime {
		return false, errors.Errorf("Cannot be issued after it expires")
	}

	// Check for a 'magic' expirationTime value, to determine if it's a specimen certificate
	if hcert.ExpirationTime == HCERT_SPECIMEN_EXPIRATION_TIME {
		return true, nil
	}

	expirationTime := time.Unix(hcert.ExpirationTime, 0)
	if expirationTime.Before(now) {
		return false, errors.Errorf("Is not valid anymore; was valid until %d", hcert.ExpirationTime)
	}

	return false, nil
}

func validateDCC(dcc *hcertcommon.DCC, now time.Time) (err error) {
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
		err = validateVaccination(vacc, now)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid vaccination statement", 0)
		}
	}

	for _, test := range dcc.Tests {
		err = validateTest(test, now)
		if err != nil {
			return errors.WrapPrefix(err, "Invalid test statement", 0)
		}
	}

	for _, rec := range dcc.Recoveries {
		err = validateRecovery(rec, now)
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

func validateVaccination(vacc *hcertcommon.DCCVaccination, now time.Time) error {
	// Disease agent
	if vacc.DiseaseTargeted != DISEASE_TARGETED_COVID_19 {
		return errors.Errorf("Disease targeted should be COVID-19")
	}

	// Allowed vaccine
	if !containsString(verifierConfig.EuropeanVerificationRules.VaccineAllowedProducts, vacc.MedicinalProduct) {
		return errors.Errorf("Medicinal product is not accepted")
	}

	// Dose number and total number of doses
	if vacc.DoseNumber < vacc.TotalSeriesOfDoses {
		return errors.Errorf("Dose number is smaller than the specified total amount of doses")
	}

	// Date of vaccination
	dov, err := time.Parse(YYYYMMDD_FORMAT, vacc.DateOfVaccination)
	if err != nil {
		return errors.Errorf("Date of vaccination could not be parsed")
	}

	nowDate := now.Truncate(24 * time.Hour).UTC()
	if nowDate.Before(dov) {
		return errors.Errorf("Date of vaccination is before the current date")
	}

	return nil
}

func validateTest(test *hcertcommon.DCCTest, now time.Time) error {
	// Disease agent
	if test.DiseaseTargeted != DISEASE_TARGETED_COVID_19 {
		return errors.Errorf("Disease targeted should be COVID-19")
	}

	// Test type
	// The current business rules don't specify that we check for specific ma values
	if !containsString(verifierConfig.EuropeanVerificationRules.TestAllowedTypes, test.TypeOfTest) {
		return errors.Errorf("Type is not allowed")
	}

	// Test result
	if test.TestResult != TEST_RESULT_NOT_DETECTED {
		return errors.Errorf("Result should be negative (not detected)")
	}

	// Test time of collection
	doc, err := time.Parse(time.RFC3339, test.DateTimeOfCollection)
	if err != nil {
		return errors.Errorf("Time of collection could not be parsed")
	}

	testValidityHours := verifierConfig.EuropeanVerificationRules.TestValidityHours
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

func validateRecovery(rec *hcertcommon.DCCRecovery, now time.Time) error {
	// Disease agent
	if rec.DiseaseTargeted != DISEASE_TARGETED_COVID_19 {
		return errors.Errorf("Disease targeted should be COVID-19")
	}

	testDate, err := time.Parse(YYYYMMDD_FORMAT, rec.DateOfFirstPositiveTest)
	if err != nil {
		return errors.Errorf("Date of first positive test could not be parsed")
	}

	// Validity
	// First calculate the validity according to our own rules
	validFromDays := verifierConfig.EuropeanVerificationRules.RecoveryValidFromDays
	validUntilDays := verifierConfig.EuropeanVerificationRules.RecoveryValidUntilDays

	validFrom := testDate.Add(time.Duration(validFromDays*24) * time.Hour)
	validUntil := testDate.Add(time.Duration(validUntilDays*24) * time.Hour)

	// If the specified validity is smaller on any side, use that specified validity
	specifiedValidFrom, err := time.Parse(YYYYMMDD_FORMAT, rec.CertificateValidFrom)
	if err == nil && specifiedValidFrom.After(validFrom) {
		validFrom = specifiedValidFrom
	}

	specifiedValidUntil, err := time.Parse(YYYYMMDD_FORMAT, rec.CertificateValidUntil)
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

func buildVerificationResult(hcert *hcertcommon.HealthCertificate, isSpecimen bool) (*VerificationResult, error) {
	// Determine issuer
	isNLDCC := "0"
	if hcert.Issuer == "NL" {
		isNLDCC = "1"
	}

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

	return &VerificationResult{
		CredentialVersion: "1",
		IsSpecimen:        isSpecimenStr,
		BirthMonth:        birthMonth,
		BirthDay:          birthDay,
		FirstNameInitial:  firstNameInitial,
		LastNameInitial:   familyNameInitial,

		IsNLDCC: isNLDCC,
	}, nil
}

func containsString(list []string, target string) bool {
	for _, elem := range list {
		if elem == target {
			return true
		}
	}

	return false
}

var dateOfBirthRegex = regexp.MustCompile(`^(?:((?:19|20)\d\d)(?:-(\d\d)(?:-(\d\d))?)?)?$`)

func parseDateOfBirth(value string) (year, month, day string, err error) {
	res := dateOfBirthRegex.FindStringSubmatch(value)
	if len(res) != 4 {
		return "", "", "", errors.Errorf("Did not conform to regex")
	}

	return res[1], res[2], res[3], nil
}
