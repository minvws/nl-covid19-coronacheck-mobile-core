package mobilecore

import (
	"testing"
)

func TestExampleQRs(t *testing.T) {
	qrAmount := len(exampleQRs)
	for i := 0; i < qrAmount; i++ {
		exampleQR := exampleQRs[i]

		r1 := ReadEuropeanCredential(exampleQR)
		if r1.Error != "" {
			t.Fatal("Could not read European credential:", r1.Error)
		}

		r2 := InitializeVerifier("./testdata")
		if r2.Error != "" {
			t.Fatal("Could not initialize verifier", r2.Error)
		}

		r3 := Verify(exampleQR)
		if r3.Status != VERIFICATION_FAILED_IS_NL_DCC {
			t.Fatal("Verification should because it's an NL DCC")
		}
		//if r3.Status != VERIFICATION_SUCCESS || r3.Error != "" {
		//	t.Fatal("Could not verify European credential:", r3.Error)
		//}

		//expectedResult := VerificationDetails{
		//	CredentialVersion: "1",
		//	IsSpecimen:        "1",
		//	FirstNameInitial:  "B",
		//	LastNameInitial:   "B",
		//	BirthDay:          "01",
		//	BirthMonth:        "01",
		//}
		//if *r3.Details != expectedResult {
		//	t.Fatal("An unexpected result was returned")
		//}
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

var exampleQRs = [][]byte{
	[]byte(`HC1:NCF220E90T9WTWGVLKO99:WA09094V-SCX*4FBBZ$0*70J+9DN03E52F3HYQ3Q4Y50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6C%63W5Y96746TPCBEC7ZKW.CX-C34EA4FXKEW.C8WEAH8MZAGY8 JC:.D.H8WJCI3D5WEAH8SH87:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96C465W5.A6UPC3JCUIA+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD3%4AIA%G7ZM81G72A6J+94G78G60IA:R8FIAA+9BC9VH9PS827A+*9AF6*09$68AFD1KF2B1F%8/STJ$U5:0B/KR/36V4+SM1I8Z%K8R44$41ZM/HM2D9.48T Q0B9ARCNO0TOS:UJA87$MOO3AOH55TJ4S1XND000FGW.UCN0F`),
}
