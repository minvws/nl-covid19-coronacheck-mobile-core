package mobilecore

import (
	"encoding/json"
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
			t.Fatal("Could not intialize verifier")
		}

		r3 := Verify(exampleQR)
		if r3.Error != "" {
			t.Fatal("Could not verify European credential:", r3.Error)
		}

		var vr *VerificationResult
		err := json.Unmarshal(r3.Value, &vr)
		if err != nil {
			t.Fatal("Could not unmarshal verification result")
		}

		expectedResult := VerificationResult{
			CredentialVersion: "1",
			IsSpecimen:        "0",
			FirstNameInitial:  "A",
			LastNameInitial:   "A",
			BirthDay:          "01",
			BirthMonth:        "01",
			IsNLDCC:           "1",
		}
		if *vr != expectedResult {
			t.Fatal("An unexpected result was returned")
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

var exampleQRs = [][]byte{
	[]byte(`HC1:NCF9S2FY7$$QDO3P7E5SL3.FJU33TTMA2PFKWOFOFVY+N:GTO.IF$AQ5NT.SZR9CPEBBP+8P6$B8GQW0I/574919KG3S8VJO6/H -DU-EIUEUMF1995ES$:LK6Q%TQQREE4C.VUHWLR+KSDV:N6LTO3QV9T3L+EYPC 02Y-7:IL4-SHZU33APHI860CBG9:G*37W503-86LNUWOEA5GUCW5RZG30ZM0RMC/BOZC5%LPH5O/M%P4+ZMTEB%CSRMQ6RI1DUMZ5TR42FQK60Y$64YA4 S7.1PBGOU1-+EB*982FJWE:9F0H7*/BH/GN50Q68WFP51FW9B7W93KH6IOND4BB1TT17+S5YL06E$BVA$B*-LB%S8QPQOIR5NG6S/XL8 6DTKXBFG-82KMS4JYWUE:09.19DGUQ6Q55OJA:9B5V2HADHAHDZGC53:*JFO62SF*VD:ZQ.O5-3CL8E+QDIAQ* 72GWOCC76Q 2SARFL$UI-O5/2F9RE5FW-1:N3N$V8ALQ%V32GK-D/7G31U8MROKV*SF99RE7L$AW000FGWELJ/ F`),
}
