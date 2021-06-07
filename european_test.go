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

		r2 := ActualInitializeVerifier("./testdata")
		if r2.Error != "" {
			t.Fatal("Could not intialize verifier")
		}

		r3 := Verify(exampleQR)
		if r3.Error != "" {
			t.Fatal("Could not verify European credential:", r3.Error)
		}
	}
}

var exampleQRs = [][]byte{
	[]byte(`HC1:NCF9S2FY7+J2DO3+8EVRG*Y1B$18INC114BM7CO/MDZ5TINGIUBZVDW-M38SF2T0YPGAF Q3DQ1G729ZGFX0YUAZL85%E332-W34BLQ*O JQPRCUX9K7G.+3Y4OS%DIVND$C8%PU1I+UPB3A+QH1VHP 8BU1KCW:.JQHTS N.B22*U8WTS:54D4Q%4+B0.A75E6W503-86LNY+NLNAR$1J P4Z5NPQU 17:TRN1K9B7ZAIN6TG9FRDWOO4J7J0R30TR3QSXJG$75YB.427QMSKCRJHP92YZ58YTQ:T%X1WAEMJGGEW$0OVSGQ01J8G5+11KJYZ2OAHXU93 QR+0*01*P0+BTX:57JM+66MAUNF7XEJIJKGM5GRB5%PJ2UDG69$M.-61POW.TZ%G+Q7X5RUGUBY4W48YPHAHF%9T/8T2$9SW8I E4R65LU+X6$KBWBU1SBM8PP%86*QWOLC8V2GLGYEQ8LJLP41PAFV.4WTZQOKDMZEU4PUDUTPTBNUK%SAUFJBV TACES9J7%-VZ:LRWO6OEVETQ6O000FGW 7O7HG`),
}
