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
			t.Fatal("Expected readability", testcase.expectedReadability, "of testcase", i, r1.Error)
		}

		r2 := InitializeVerifier("./testdata")
		if r2.Error != "" {
			t.Fatal("Could not initialize verifier", r2.Error)
		}

		r3 := verify(testcase.qr, now)
		didError := r3.Error != ""
		expectError := testcase.expectedStatus == VERIFICATION_FAILED_ERROR
		if didError != expectError {
			t.Fatal("Presence of error is", didError, "while expecting", expectError, r3.Error)
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
	expectedStatus      int
	expectedDetails     *VerificationDetails
	expectedReadability bool
}

var defaultQR = []byte(`HC1:NCFA20690T9WTWGVLK-49NJ3B0J$OCC*AX*4FBBD%1*702T9DN03E53F3560+$GY50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6C%63W5Y96.96TPCBEC7ZKW.C%DDDZC.H8B%E5$CLPCG/D%DD*X8AH8MZAGY8 JC0/DAC81/DMPCG/DFUCL+9VY87:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96D464W5B56UPCBJCOT9+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD3%4AIA%G7ZM81G72A6J+9RG7SNAH7B5OAU1B2X6LH86T9N096*6G%6AF60Z9P48Q1RI.3/LC8LNQ5RK/4N$4E0W WMH/3OQC2:B0WV4JQS0DH-D$23UJNUL6U*9GDIFL06+61DHX85TD34009K5DIURQAK6RT5B000FGWI%3L*E`)
var nlQR = []byte(`HC1:NCFA20690T9WTWGVLK-49NJ3B0J$OCC*AX*4FBBD%1*70J+9DN03E53F3560.PQY50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6C%63W5Y96.96TPCBEC7ZKW.C%DDDZC.H8B%E5$CLPCG/D%DD*X8AH8MZAGY8 JC0/DAC81/DMPCG/DFUCL+9VY87:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96D464W5B56UPCBJCOT9+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD3%4AIA%G7ZM81G72A6J+9RG7SNAH7B5OAU1B2X6LH86T9N096*6G%6AF60Z9498-.ETWJB/ON3B+XAK7DF%HPZE9$BYKQUOF4:F25NZD0P6E+-0D%C4-3ISRA:PLO0PN6FN9HN0UUB7BBC%MB EXP8HE821WV%K000FGW6%II9F`)
var defaultDetails = &VerificationDetails{"1", "A", "D", "15", "01", "1"}

var wholeNumberFloatDoseQR = []byte(`HC1:NCF%RN%TS3DH0RGPJB/IB-OM7533SR769CIN3XHW2KWP5IJBOJAFYHPI1SA3/-2E%5G%5TW5A 6+O6XL69/9-3AKI6/Q6LEQZ76UW6S$99Q9E$BDZIJ7JGOIRHSK2C%0KJZIC0JYPI2SSK S.-3O4UBZI92K3TSH7JPOJZ0KRPI/JTPCTHABVCNAHLW 70SO:GOLIROGO3T59YLLYP-HQLTQV*OOGOBR7Z6NC8P$WA3AA9EPBDSM+QFE4:/6N9R%EPXCROGO3HOWGOKEQ395WDUK:V9Z0O598+94DM.J9WVHWVH+ZE5%PUU1NTIUZUG-VVLIWQHSUAOP6OH6XO9IE5IVU5P2-GA*PE+E6MPO+SEMF2/GA H2.GA JG TUAJ9WLIFO5HI8J.V/I8*Z7ON1Z:LBYFEKG*ZNLT7P 7:%BU*R/L0..P5:PGSG7 9RWIXJ40H1-BW42R$D8*ZSDTOVETQTB+:RHALY3WKAJVINC/RS$B.FC+.TAWPHWC5:1/77I*5+7N UMJRF/ORN 9AKF:ONZQNT4L72V6H6$%9224U50-BWLTUB5`)
var fractionalFloatDoseQR = []byte(`HC1:NCF%RN%TS3DH0RGPJB/IB-OM7533SR769FLT3XHW2KWP5IJBOJAFYHPI1SA3/-2E%5G%5TW5A 6+O6XL69/9-3AKI6/Q6LEQZ76UW6S$99Q9E$BDZIJ7JGOIRHSK2C%0KJZIC0JYPI2SSK S.-3O4UBZI92K3TSH7JPOJZ0KRPI/JTPCTHABVCNAHLW 70SO:GOLIROGO3T59YLY1S7HOPC5NDOEC5L64HX6IAS3DS2980IQ.DPL95OD6%28%%BPHQOGO+GOT*OBR7 Z4VBNL+1U46UF5/NVVAW+PPWC5PF6846A$QY76UW6VY9U3Q5WUZE98T5LAAY0Q$UPR$5:NLOEPNRAE69K PBKPC21%.PTM9*H9699LN9O11$DPPF5PK9CZL*H1VUUME1L8VNF6H*MF U8LELE1*.1-9VW11B%EHE14+1E*U6W1-Q6/LAPMHO99Y0VL+A*JKMJ58QKSAQQEHR8KS+D5DOGWF4EC6*MKSLFG5:SRWX1T554EWCNSQ%KD-T487*7H9DDF:KO:LKNVK/DHPUC+D1H0A:M88G000FGWSXB2 F`)

var qrTestcases = []*qrTestcase{
	{defaultQR, VERIFICATION_SUCCESS, defaultDetails, true},
	{defaultQR[:50], VERIFICATION_FAILED_ERROR, nil, false},
	{defaultQR[6:], VERIFICATION_FAILED_UNRECOGNIZED_PREFIX, nil, false},
	{nlQR, VERIFICATION_FAILED_IS_NL_DCC, nil, true},

	// Special case of a missing prefix because of a T-Systems app problem
	{defaultQR[4:], VERIFICATION_SUCCESS, defaultDetails, false},

	// Special case of float values that should be ints (Ireland)
	{wholeNumberFloatDoseQR, VERIFICATION_SUCCESS, defaultDetails, true},
	{fractionalFloatDoseQR, VERIFICATION_FAILED_ERROR, defaultDetails, false},
}
