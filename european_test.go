package mobilecore

import (
	"testing"
	"time"
)

func TestExampleQRs(t *testing.T) {
	now := time.Unix(1627462000, 0)

	for i, testcase := range qrTestcases {
		r1 := ReadEuropeanCredential(testcase.qr)
		couldRead := r1.Error == ""
		if couldRead != testcase.expectedReadability {
			t.Fatal("Expected readability", testcase.expectedReadability, "of testcase", i)
		}

		r2 := InitializeVerifier("./testdata")
		if r2.Error != "" {
			t.Fatal("Could not initialize verifier", r2.Error)
		}

		r3 := verify(testcase.qr, now)
		didError := r3.Error != ""
		expectError := testcase.expectedStatus == VERIFICATION_FAILED_ERROR
		if didError != expectError {
			t.Fatal("Presence of error is", didError, "while expecting", expectError)
		}

		if r3.Status != testcase.expectedStatus {
			t.Fatal("Expected status", testcase.expectedStatus, "of testcase", i, "but got", r3.Status)
		}

		if testcase.expectedStatus == VERIFICATION_SUCCESS && *r3.Details != *testcase.expectedDetails {
			t.Fatal("Unexpected details for testcase", i)
		}
	}
}

func TestParseBirthDay(t *testing.T) {
	cases := [][]string{
		{"1980-01-12", "valid", "1980", "01", "12"},
		{"2006-06-24", "valid", "2006", "06", "24"},
		{"2020-12-05", "valid", "2020", "12", "05"},
		{"1980-01", "valid", "1980", "01", ""},
		{"1980", "valid", "1980", "", ""},
		{"", "valid", "", "", ""},

		{"1980-1-12", "invalid"},
		{"1980-1--12", "invalid"},
		{"1980-1-12", "invalid"},
		{"1980-a1-12", "invalid"},

		// We don't actually check if the date exists
		{"1980-13-12", "valid", "1980", "13", "12"},
		{"1980-02-31", "valid", "1980", "02", "31"},
		{"1980-06-41", "valid", "1980", "06", "41"},
		{"1980-31", "valid", "1980", "31", ""},
	}

	for i, c := range cases {
		y, m, d, err := parseDateOfBirth(c[0])
		if c[1] == "valid" {
			if err != nil {
				t.Fatal("Error on valid case", i)
			}

			if y != c[2] || m != c[3] || d != c[4] {
				t.Fatal("Invalid value on case", i)
			}
		} else {
			if err == nil {
				t.Fatal("No error on invalid case", i)
			}
		}
	}
}

type qrTestcase struct {
	qr                  []byte
	expectedStatus      VerificationStatus
	expectedDetails     *VerificationDetails
	expectedReadability bool
}

var defaultQR = []byte(`HC1:NCFA20690T9WTWGVLK-49NJ3B0J$OCC*AX*4FBBD%1*702T9DN03E53F3560+$GY50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6C%63W5Y96.96TPCBEC7ZKW.C%DDDZC.H8B%E5$CLPCG/D%DD*X8AH8MZAGY8 JC0/DAC81/DMPCG/DFUCL+9VY87:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96D464W5B56UPCBJCOT9+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD3%4AIA%G7ZM81G72A6J+9RG7SNAH7B5OAU1B2X6LH86T9N096*6G%6AF60Z9P48Q1RI.3/LC8LNQ5RK/4N$4E0W WMH/3OQC2:B0WV4JQS0DH-D$23UJNUL6U*9GDIFL06+61DHX85TD34009K5DIURQAK6RT5B000FGWI%3L*E`)
var nlQR = []byte(`HC1:NCFA20690T9WTWGVLK-49NJ3B0J$OCC*AX*4FBBD%1*70J+9DN03E53F3560.PQY50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6C%63W5Y96.96TPCBEC7ZKW.C%DDDZC.H8B%E5$CLPCG/D%DD*X8AH8MZAGY8 JC0/DAC81/DMPCG/DFUCL+9VY87:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96D464W5B56UPCBJCOT9+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD3%4AIA%G7ZM81G72A6J+9RG7SNAH7B5OAU1B2X6LH86T9N096*6G%6AF60Z9498-.ETWJB/ON3B+XAK7DF%HPZE9$BYKQUOF4:F25NZD0P6E+-0D%C4-3ISRA:PLO0PN6FN9HN0UUB7BBC%MB EXP8HE821WV%K000FGW6%II9F`)
var defaultDetails = &VerificationDetails{"1", "A", "D", "15", "01", "1"}

var qrTestcases = []*qrTestcase{
	{defaultQR, VERIFICATION_SUCCESS, defaultDetails, true},
	{defaultQR[:50], VERIFICATION_FAILED_ERROR, nil, false},
	{defaultQR[6:], VERIFICATION_FAILED_UNRECOGNIZED_PREFIX, nil, false},
	{nlQR, VERIFICATION_FAILED_IS_NL_DCC, nil, true},

	// Special case of a missing prefix because of a T-Systems app problem
	{defaultQR[4:], VERIFICATION_SUCCESS, defaultDetails, false},
}
