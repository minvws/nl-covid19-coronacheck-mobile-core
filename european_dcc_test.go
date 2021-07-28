package mobilecore

import (
	"encoding/json"
	"fmt"
	hcertcommon "github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHCerts(t *testing.T) {
	var validTime int64 = 1625000000
	var earlyTime int64 = 1615000000
	var lateTime int64 = 1635000000

	testCases := []hcertTestCase{
		{nil, validTime, false, true},
		{nil, earlyTime, false, false},
		{nil, lateTime, false, false},
		{singleStructChange(42, "ExpirationTime"), validTime, true, true},
		{singleStructChange(earlyTime, "ExpirationTime"), validTime, false, true},
	}

	for i, testCase := range testCases {
		hcert := getHcert("", testCase.changes)
		isSpecimen, err := validateHcert(hcert, time.Unix(testCase.unixTime, 0))
		if isSpecimen != testCase.isSpecimen {
			t.Fatal("Got wrong isSpecimen", isSpecimen, "for test case", i)
		}

		isValid := err == nil
		if isValid != testCase.isValid {
			t.Fatal("Got wrong isValid", isValid, "for test case", i)
		}
	}
}

func TestDCCs(t *testing.T) {
	validVaccTime := "2021-07-01"
	rules := verifierConfig.EuropeanVerificationRules

	testCases := []dccTestCase{
		// Different amount of statements
		{"V", rules, nil, validVaccTime, true},
		{"", rules, nil, validVaccTime, false},
		{"VV", rules, nil, validVaccTime, false},
		{"VT", rules, nil, validVaccTime, false},

		// Date of birth
		{"V", rules, dobChange("1990-01"), validVaccTime, true},
		{"V", rules, dobChange("1990"), validVaccTime, true},
		{"V", rules, dobChange(""), validVaccTime, true},
		{"V", rules, dobChange("1890-01-01"), validVaccTime, false},
		{"V", rules, dobChange("1990-01--01"), validVaccTime, false},
		{"V", rules, dobChange("190-01-01"), validVaccTime, false},
		{"V", rules, dobChange("90-01-01"), validVaccTime, false},

		// Names
		{"V", rules, nameChange("", "StandardizedFamilyName"), validVaccTime, true},
		{"V", rules, nameChange("", "StandardizedGivenName"), validVaccTime, true},
		{"V", rules,
			append(
				nameChange("", "StandardizedFamilyName"),
				nameChange("", "StandardizedGivenName")...,
			),
			validVaccTime, false,
		},

		// Vaccination
		//
		// Vaccination time
		{"V", rules, nil, "2021-06-07", false},
		{"V", rules, nil, "2021-06-08", false},
		{"V", rules, nil, "2021-06-09", false},
		{"V", rules, nil, "2021-06-21", false},
		{"V", rules, nil, "2021-06-22", true},
		{"V", rules, nil, "2023-01-01", true},

		// Disease targeted
		{"V", rules, vaccChange("840539007", "DiseaseTargeted"), validVaccTime, false},

		// Medicinal product
		{"V", rules, vaccChange("EU/1/20/1528", "MedicinalProduct"), validVaccTime, true},
		{"V", rules, vaccChange("EU/1/20/1507", "MedicinalProduct"), validVaccTime, true},
		{"V", rules, vaccChange("EU/1/21/1529", "MedicinalProduct"), validVaccTime, true},
		{"V", rules, vaccChange("EU/1/20/1525", "MedicinalProduct"), validVaccTime, true},
		{"V", rules, vaccChange("Sputnik-V", "MedicinalProduct"), validVaccTime, false},

		// Doses
		{"V", rules, vaccDoseChange(0, 0), validVaccTime, true},
		{"V", rules, vaccDoseChange(1, 1), validVaccTime, true},
		{"V", rules, vaccDoseChange(2, 2), validVaccTime, true},
		{"V", rules, vaccDoseChange(4, 2), validVaccTime, true},
		{"V", rules, vaccDoseChange(0, 1), validVaccTime, false},
		{"V", rules, vaccDoseChange(1, 2), validVaccTime, false},

		// Insufficient information in vaccination date
		{"V", rules, vaccChange("2021-06-1", "DateOfVaccination"), validVaccTime, false},
		{"V", rules, vaccChange("2021-06", "DateOfVaccination"), validVaccTime, false},
		{"V", rules, vaccChange("2021-1", "DateOfVaccination"), validVaccTime, false},
		{"V", rules, vaccChange("2021", "DateOfVaccination"), validVaccTime, false},
		{"V", rules, vaccChange("", "DateOfVaccination"), validVaccTime, false},

		// Special case handling
		//
		// GR: Whitespaces in decoded mp field
		{"V", rules, vaccChange("  EU/1/20/1528    ", "MedicinalProduct"), validVaccTime, true},
		{"V", rules, vaccChange("\u00A0\u2001EU/1/20/1528\t", "MedicinalProduct"), validVaccTime, true},
		{"V", rules, vaccChange(" Sputnik-V ", "MedicinalProduct"), validVaccTime, false},

		// BG: Invalid information (like ISO8601 timestamps) in dates
		{"V", rules, dobChange("1990-01-01T01:30Z"), validVaccTime, true},
		{"V", rules, dobChange("1990-01-01meh"), validVaccTime, true},
		{"V", rules, vaccChange("2021-06-08T14:30Z", "DateOfVaccination"), validVaccTime, true},
	}

	for i, testCase := range testCases {
		now, err := time.Parse("2006-01-02", testCase.date)
		if err != nil {
			t.Fatal("Could not parse date")
		}

		hcert := getHcert(testCase.statements, testCase.changes)
		err = validateDCC(hcert.DCC, testCase.rules, now)
		isValid := err == nil
		if isValid != testCase.isValid {
			errStr := ""
			if err != nil {
				errStr = fmt.Sprintf("(%s)", err.Error())
			}

			t.Fatalf("Got wrong isValid %t for test case %d %s", isValid, i, errStr)
		}
	}
}

func TestHcertResult(t *testing.T) {
	baseResult := VerificationDetails{
		"1", "A", "B", "13", "03", "0",
	}

	// Rest of the test cases
	testCases := []resultTestCase{
		{
			nil,
			nil,
		},
		{
			nameChange("", "StandardizedFamilyName"),
			singleStructChange("", "LastNameInitial"),
		},
		{
			nameChange("", "StandardizedGivenName"),
			singleStructChange("", "FirstNameInitial"),
		},
		{
			dobChange("1950-03"),
			singleStructChange("XX", "BirthDay"),
		},
		{
			dobChange("1950"),
			append(
				singleStructChange("XX", "BirthDay"),
				singleStructChange("XX", "BirthMonth")...,
			),
		},
	}

	for i, testCase := range testCases {
		hcert := getHcert("V", testCase.hcertChanges)
		expectedResult := getDetails(baseResult, testCase.resultChanges)

		res, err := buildVerificationDetails(hcert, false)
		if err != nil {
			t.Fatal("Error when building result for test case", i)
		}

		if *res != *expectedResult {
			t.Fatal("Unexpected result for test case", i)
		}
	}
}

type hcertTestCase struct {
	changes    []structChange
	unixTime   int64
	isSpecimen bool
	isValid    bool
}

type dccTestCase struct {
	statements string
	rules      *europeanVerificationRules
	changes    []structChange
	date       string
	isValid    bool
}

type resultTestCase struct {
	hcertChanges  []structChange
	resultChanges []structChange
}

type structChange struct {
	path  []interface{}
	value interface{}
}

func dobChange(value interface{}) []structChange {
	path := []interface{}{"DCC", "DateOfBirth"}
	return singleStructChange(value, path...)
}

func nameChange(value interface{}, key string) []structChange {
	path := []interface{}{"DCC", "Name", key}
	return singleStructChange(value, path...)
}

func vaccChange(value interface{}, key string) []structChange {
	path := []interface{}{"DCC", "Vaccinations", 0, key}
	return singleStructChange(value, path...)
}

func vaccDoseChange(dn, sd int) []structChange {
	return append(
		vaccChange(dn, "DoseNumber"),
		vaccChange(sd, "TotalSeriesOfDoses")...,
	)
}

func singleStructChange(value interface{}, path ...interface{}) []structChange {
	return []structChange{
		{path, value},
	}
}

func getHcert(statements string, changes []structChange) *hcertcommon.HealthCertificate {
	var hcert *hcertcommon.HealthCertificate
	_ = json.Unmarshal(baseHcertJson, &hcert)

	// Add vaccination, recovery or tests
	for _, statement := range strings.Split(statements, "") {
		if statement == "V" {
			var vacc *hcertcommon.DCCVaccination
			_ = json.Unmarshal(vaccinationJson, &vacc)
			hcert.DCC.Vaccinations = append(hcert.DCC.Vaccinations, vacc)
		} else if statement == "R" {
			var rec *hcertcommon.DCCRecovery
			_ = json.Unmarshal(recoveryJson, &rec)
			hcert.DCC.Recoveries = append(hcert.DCC.Recoveries, rec)
		} else if statement == "T" {
			var test *hcertcommon.DCCTest
			_ = json.Unmarshal(testJson, &test)
			hcert.DCC.Tests = append(hcert.DCC.Tests, test)
		} else {
			panic("Invalid statement identifier " + statement)
		}
	}

	return applyStructChanges(hcert, changes).(*hcertcommon.HealthCertificate)
}

func getDetails(res VerificationDetails, changes []structChange) *VerificationDetails {
	return applyStructChanges(&res, changes).(*VerificationDetails)
}

func applyStructChanges(s interface{}, changes []structChange) interface{} {
	// Make changes
	for _, change := range changes {
		// Walk the path, either a struct field or an slice index
		target := reflect.ValueOf(s).Elem()
		for _, pathElem := range change.path {
			target = reflect.Indirect(target)

			switch tp := pathElem.(type) {
			case string:
				target = target.FieldByName(tp)
			case int:
				target = target.Index(tp)
			}
		}

		// Set the value for the appropriate type
		switch tv := change.value.(type) {
		case string:
			target.SetString(tv)
		case int:
			target.SetInt(int64(tv))
		case float32:
			target.SetFloat(float64(tv))
		case float64:
			target.SetFloat(tv)
		}
	}

	return s
}

var baseHcertJson = []byte(`
{
  "credentialVersion": 1,
  "issuer": "NL",
  "issuedAt": 1620000000,
  "expirationTime": 1630000000,
  "dcc": {
    "ver": "1.0.0",
    "dob": "1950-03-13",
    "nam": {
      "fn": "Badelaar",
      "fnt": "BADELAAR",
      "gn": "Aaltje",
      "gnt": "AALTJE"
    },
    "v": null,
    "t": null,
    "r": null
  }
}
`)

var vaccinationJson = []byte(`{
  "tg": "840539006",
  "vp": "1119349007",
  "mp": "EU/1/20/1507",
  "ma": "ORG-100030215",
  "dn": 2,
  "sd": 2,
  "dt": "2021-06-08",
  "co": "NLD",
  "is": "Ministry of Health Welfare and Sport",
  "ci": "074f34f4-7972-469e-b6cf-8a5f2e8de110"
}`)

var recoveryJson = []byte(`{
  
}`)

var testJson = []byte(`{
  
}`)
