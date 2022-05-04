package mobilecore

import (
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/localsigner"
	"github.com/privacybydesign/gabi"
	gabipool "github.com/privacybydesign/gabi/pool"
	"strconv"
	"testing"
	"time"
)

var testKeyIdentifier = "testPk"

func TestInitialization(t *testing.T) {
	r1 := InitializeHolder("./testdata")
	if r1.Error != "" {
		t.Fatal("Could not initialize holder:", r1.Error)
	}

	// Initialize verifier with testdata
	r2 := InitializeVerifier("./testdata")
	if r2.Error != "" {
		t.Fatal("Could not initialize verifier:", r2.Error)
	}
}

func TestFlow(t *testing.T) {
	credentialAmount := 3
	credentialVersion := 3
	clockSkewSeconds := int64(120)
	credentialAttributes := buildCredentialsAttributes(credentialAmount)

	// Generate holdercore secret key
	r3 := GenerateHolderSk()
	if r3.Error != "" {
		t.Fatal("Could not generate holdercore secret key:", r3.Error)
	}

	// Create a signer and issuer for the tests
	keys := []*localsigner.Key{
		{
			KeyIdentifier: testKeyIdentifier,
			PkPath:        "./testdata/pk.xml",
			SkPath:        "./testdata/sk.xml",
		},
	}

	ls, err := localsigner.New(keys, gabipool.NewRandomPool())
	if err != nil {
		t.Fatal("Could not create local signer:", err)
	}

	iss := issuer.New(ls)
	pim, err := iss.PrepareIssue(&issuer.PrepareIssueRequestMessage{
		KeyIdentifier:    testKeyIdentifier,
		CredentialAmount: credentialAmount,
	})
	if err != nil {
		t.Fatal("Could not prepare issue:", err)
	}

	// Issuance dance
	ismJson, err := json.Marshal(pim)
	if err != nil {
		t.Fatal("Could not JSON marshal issue specification message:", err)
	}

	r4 := CreateCommitmentMessage(r3.Value, ismJson)
	if r4.Error != "" {
		t.Fatal("Could not create commitment message:", r4.Error)
	}

	icm := new(gabi.IssueCommitmentMessage)
	err = json.Unmarshal(r4.Value, icm)
	if err != nil {
		t.Fatal("Could not unmarshal issue commitment message:", err)
	}

	im := &issuer.IssueMessage{
		PrepareIssueMessage:    pim,
		IssueCommitmentMessage: icm,
		CredentialsAttributes:  credentialAttributes,
		CredentialVersion:      credentialVersion,
		KeyIdentifier:          testKeyIdentifier,
	}

	ccms, err := iss.Issue(im)
	if err != nil {
		t.Fatal("Could not issue create credential messages:", err)
	}

	ccmsJson, err := json.Marshal(ccms)
	if err != nil {
		t.Fatal("Could not marshal create credential messages:", err)
	}

	r5 := CreateCredentials(ccmsJson)
	if r5.Error != "" {
		t.Fatal("Could not create credential:", r5.Error)
	}

	// Check back attributes returns on creation
	var r5Values []*CreateCredentialResultValue
	err = json.Unmarshal(r5.Value, &r5Values)
	if err != nil {
		t.Fatal("Could not unmarshal create credential result values:", err)
	}

	if credentialAmount != len(r5Values) {
		t.Fatal("Invalid amount of create credential result values")
	}

	for i := 0; i < credentialAmount; i++ {
		val := r5Values[i]

		err := areAttributesEqualWithCredentialVersion(credentialAttributes[i], val.Attributes)
		if err != nil {
			t.Fatal("Attributes do not match attributes from create credentials:", err)
		}

		credJson, err := json.Marshal(val.Credential)
		if err != nil {
			t.Fatal("Could not marshal credential:", err)
		}

		// Read
		r6 := ReadDomesticCredential(credJson)
		if r6.Error != "" {
			t.Fatal("Could not read credential:", r6.Error)
		}

		err = checkAttributesJson(credentialAttributes[i], r6.Value)
		if err != nil {
			t.Fatal(err)
		}

		// Disclosure with both verification policies, against both discosure policies
		for _, disclosurePolicy := range []string{DISCLOSURE_POLICY_1G, DISCLOSURE_POLICY_3G} {
			r7 := Disclose(r3.Value, credJson, disclosurePolicy)
			if r7.Error != "" {
				t.Fatal("Could not disclose credential:", r6.Error)
			}

			for _, verificationPolicy := range []string{VERIFICATION_POLICY_1G, VERIFICATION_POLICY_3G} {
				r8 := Verify(r7.Value, verificationPolicy)

				// Disclosure 3G and verification 1G shouldn't verify
				if disclosurePolicy == DISCLOSURE_POLICY_3G && verificationPolicy == VERIFICATION_POLICY_1G {
					if r8.Status != VERIFICATION_FAILED_ERROR || r8.Error == "" {
						t.Fatal("Disclosure 3G with verification 1G should fail")
					}

					continue
				}

				// Only the first two credentials should validate due to validFrom in future
				if i < 2 {
					if r8.Status != VERIFICATION_SUCCESS || r8.Error != "" {
						t.Fatal("Could not verify credential:", r8.Error)
					}

					if *r8.Details != attributesToVerificationDetails(credentialAttributes[i]) {
						t.Fatal("Credential attributes do not correspond with verification details")
					}
				}

				if i > 1 && (r8.Status != VERIFICATION_FAILED_ERROR || r8.Error == "") {
					t.Fatal("Credential should not validate due to validFrom in future")
				}
			}
		}

		// Disclose again with clock skew
		r9 := DiscloseWithTime(r3.Value, credJson, DISCLOSURE_POLICY_3G, time.Now().Unix()+clockSkewSeconds)
		if r9.Error != "" {
			t.Fatal("Could not disclose credential with time: ", r9.Error)
		}

		// Verify clock skewed credential with current time which should fail
		r10 := Verify(r9.Value, VERIFICATION_POLICY_3G)
		if r10.Error == "" {
			t.Fatal("Clocked skewed credential should not verify")
		}

		r11 := VerifyWithTime(r9.Value, VERIFICATION_POLICY_3G, time.Now().Unix()+clockSkewSeconds)
		if i < 2 && r11.Error != "" {
			t.Fatal("Clock skewed credential with manual time setting should verify:", r11.Error)
		}
	}
}

func TestUnrecognizedCred(t *testing.T) {
	someQR := []byte(`1K9P/3FD!C.%2H5N4$**$IVY+3$`)

	r1 := Verify(someQR, VERIFICATION_POLICY_3G)
	if r1.Status != VERIFICATION_FAILED_UNRECOGNIZED_PREFIX {
		t.Fatal("QR could should have status unrecognized")
	}
}

func TestDeniedProof(t *testing.T) {
	deniedQr := []byte(`NL2:3QYLJN7UNC EJZ2I/1AJ/NLOSBX8O/N7*SQ376YP86E:U6ZO:5K UXRBMCARHV4ETZT1 -3-%CKD6T4MLMGS%:-S+U8EMJV0+3JINFCK4RYSQR8G/-JC M-L-VXS14XXNF-.-E 1:7H1X2GINPH0%YRP+/B.GSP4RHEDXRYTKO/VL1BC39X6MDM6ES+HPKH9VUS$XMYKU.%PJCCQT74HRY8$Q73I2P-77D$8NN.TK9PX4+/:8KR39HC*ZG86QJ9QKKJ.MAFYCPPV3BI*IYARY**J%WQAXX/-5KARDLZ9LXXIL%KKYF.X.JVM0$W0P4ATK66EQUI/R/7Z2TOHE4H:163J:7D5S X*ULK1VVYRC-4.PTE$ZJOWCGJR$UQAACJ1QAIXJ/SA1M1W NJBQQP56YY2V7YEP8E6:UD5AXMAXV*.DG.MW QQ/3QPEHR-YQIA0:85T+W4YC087A$MQ825173D/LBA0GL:88/S4Q8GNP2KCAD0LW$R1UXUH0PVCO4--1:+JH $PG6ZPORBHG7O4HU63-.1JZ9DUDACOHYZ869Y*X7TG+PYRRCY08*Q9DCAT0T:+HJ9B0ZS.NJIEHFTVEO8Y+L6$*H :TTSGRAS M9U8SLC+33/C3*86HAOW6PIPP13 HF+38%8EA$+7O+6+URI09%LDJX872V8 VM8O:Z1H0FIUVKGBBP4OL$Z0E8$KJAIUC6%8Y2BHX+95P.JP8CM1SUYF *J3UB3.KW81PJ$-8288C17NTCYFMI0%KB1GO07ZKB$R:DYFO+Q9:GA+9EE40Q3GQ53I-*:+*2U  LS 9O9Y2V7TZTO.FB5NSNMCOZX65WU%CYEJH$%9585A126-T5XB3%UVX3ULIQ5XJ7H.C%QG4RG$P L:C6WC*6N5X646 SJATTH85P5QJE/K3PU80CVYN+VZ9+8C8IPT+%T1YF50+4.NJPI12KM0..1ZDK/$NEZBVW-2TM+%V9$N00YUQSO 57M1JE-M2TT%%9RXHDWH/BFX3ZV/V6.S5F6BPJGZPJ4V$*K6ACOS6P:XFS-T-RW21H52 65VUSS*P505ILMZN%9DNRO42NKQKACHG/1GNLS V0OUUJL*9PZ/06SS9/GCFKIFW39KJ/ IVB10WE%T1C9MS2J4BR/9E$F5O5 DYPNVV9Y I0H4MRC5AO36UNWBRMCUPGCYZH+FIELM-R4:7L3L/L3F5WL4.-73494V.X67$*H$S9X51EX:6VRUMEBT224 +FW/0*4.V75:W:HXLB*Z6DGK27L.ZY-S4LZOP.HIWG:/PM9L6PVN.$PZDS$6$0KAL8OT/TM`)
	r1 := Verify(deniedQr, VERIFICATION_POLICY_3G)
	if r1.Status != VERIFICATION_FAILED_ERROR {
		t.Fatal("QR could should have status error")
	}
}

type verificationPolicyTestcase struct {
	qr             []byte
	policy         string
	expectedResult int
}

func TestVerificationPolicy(t *testing.T) {
	verificationTime := time.Unix(1644320000, 0)
	categoryAbsentQR := []byte(`NL2:EV%4XNSNCCXRR4PX%E75H1XWMZUQ:YQL2QXD$*3SUHTIWIPV0.%JHLCHIV$QU-UC*QJ*-XIGTF68NZ91KZV.*SXKR3E/$NNEVT8U76TE4LQ5XV+MDQO-9%XA%BOQTF%%JZMMU-MSL:*J97BN*W*-9%IX7385HNDISSCO%8*:Y0*C ISOZKSOE*PKO3N3C QW+F97JR%15$A86FYZ%56W6GACZ::RKX:E/VOIE%3S.0AJ+T6$-%S4PEM53IXOZ.4PL%3:9DBLVO1FY7WD*47K/:.RTIRA$1E6D7%BW6D 5-  8.4$6U V:2 2BM$+ST8$I38I%+CJW $CS2Y+WVL2MO4JGIWS.E7* UGQB01K*JJ7-3Z8KDJ-+NU%GX I5X%SVZ:K %G%09$WGAK4P1N54WBXTI$ *IWJ5$LH3+RP8.P/OOUV-OZRPYMCOU2JCCVWS59..KNXE8MN.FNA9P-KHH-R5Z J980%KAKY1/FETCA9-38N4M 7XLQO+QR9VGN5$:63H OZOIYTJLNP$$9:H0P QDC3YWIXZCRF4:NFVMV2$F91T:WKK70I92OCR0+BD5 1WP7XBV*I S6KT:.-K7DG4RMU42CJBIM/NE+Y7O71O+EX BMXUW:5ZH/UC36ZR/.5X:8NOCLE+8J3E$ *FUOC0WMK5Q*7K4J-ZI4S8OBNB+7MUP2F9O+28%.V/PX4TODGYSZ+BB $BVB6O63:22JY$9M%9PQS2EYK40MGB+ Q/LIJGFPVTHBHIYDMD2I6NF%B37XP/EOZ/%6MXC-6:29XMVDZ//47S9*881XUL6$9LGIYRIZRP5IU77GC%Z6E RC6REZO884R R30BRL13F0/82-D1 5X/HG$U6R%QIC+%Q%A/E*HI1*49LFP.TN%I2C*5K67NKYFA1+VYYE3SP:-FOQ.5G+NSL55VB%H24HV03VBPC4Z8HPGLHM3Z%Q81V0J*4MYFFH 89J2/CXC.OU1AOVT :VNQ+$%WYEY979107%F*/+IRE01:2O%YU0NT560P2::X1G $- 6:D23S0M6%:6.9J1:E7UK6-D/V.*UZN4V 6.GW:J%V6-Z%38EETP%U4S6$KVWPUTHAR6%OE RF5NNS6V7LMN9SB.P%BBDWO:J9%IBJR+9 W5SB0K-R/ K:*Z.K CZ-$/HFR+A$IDF.GRN78-.3NYK*$BEAXTP%4Z+UW+D:Q48UDZ15*VSLPDUURE5LI:PU1WX5A3NJBW$R-N3TZ31F.QI2+T.+I+K/2H5P8-OZSMK/$G 0TOAKSCKGSLV:0OI$NRWX1UDGLOJXDN217QZ.A2 *M7XBY8W`)
	categoryEmptyQR := []byte(`NL2:/CK-/8OJSU0 G6NWMMREIU:64N3EEKUP4LT8WQ66FUS+7TN::RGV6KAZ HTQZN4$J3MRK8+Q 6LO:OV3I$-/T4NS1CEC8+ILAUO0+FK+2 6B5W0SC:/H1Z/SUP8N2W3FR:EOVH9C3F/++-81Z7$8HO5KI3 .N/71J1.ZHD 85Z/12BK0AYM4K+SR1XW3AKXFW.X4.K37739ZIVADX*CKM4ZF+/3**N%B4LXE81-XEH.VL0H.-0IYG5*RVTUXRKLRIMX/5.HC70C4IA48RN5CD:6.SH$-FINE8T+D7-87W9P3LF+ *63256KRV AB+SI0RFB4ZO9N:%6/UNFI9Q0EBN195%AT-ISYI/1XRP6X13K:5-Q EP-1K/+*+VBA.G1FTXPV2R*RLG* NXM 5ZD1SUEWP93M35:1S-*S5%AM6Q+RM7:MET8:8CCGZNL T*0+CQYD+A2KVZ4.7J8 P%W/NV:EZT3CTRI.B97HVGPJVRT668W3IJ44L14%62AQQE9NYDJ92%B$1+KDLPFZYFUA8U21-AZ71X0G0L2HUZX0D3B /M%FSTP7%*PAP1M$S8D6B-P*8JHHD7.MC$N1F7K+4AHVGWC0-GRE0AKBDW2-JJYK50*LJ$%GBU+P-POT8KJ9QO/C83YEFSSM9WB$9BJAAB7L+TFDQAV **9Y0P05$P-YI8Z%.YL OE89Y7PXMXM0J.3SEZ$W*425XC S1HMV66U G1Z4/.3EU66:Y+I89$4NEN/*/:%01*J8-%VI*+XOG4-ISI-3A-H.Z$.ABB$W-$6EZB$A2SG3PCK4VOBIQ4P0-Z6ODLD1S3CBL:/3S/IH:OAGTOW/JB5XL0FK0:ZRWA75P6TN:4LKX4MHVR8ETEMV97ESAH2O+XKZ3CIZ17-J%RT6CXA*R$ZQKK%EJA::%8.H$QP*+I*:0QBG00O188/HS$ M65**59R1:VGEGBA$A4WTDQYFKGE*F3K7*KRZFI2AU70UXMM Q +A601L1$:RSGOMLZZLB5OT91U0NJ6%1PN3JCH7P4*5TBF9X4C0G:PY C254BYCBHWTU62PYB5VI*9O9%B5XF61WE3OBLVLVLE3.MI965*EZTVOBEIP0+$$3X.6:-8KWNVW 9-C6*A2M8/KVR+K /%LQX21AYA1CRE4D$ SK4D5EGNKJN:QS83TL303R08MMV-0ZYKG+0XVXNZ8W$8GI558Z+$O04P19:YLL4S :HT8RWUM:P7Z5M144KU+JYODFEFV7CL7B%IDDIPSVJ8CE77BEI7XEK/X55$U5:YQYZJ$OJU/SZNV*08LUTC .7:PVT%E+/F93ZKYU-6AOCY`)
	category1GQR := []byte(`NL2:1F7*0H-FZ4% O9PJG/TZ$:OYOUGA9BKT+J7E6IGBBVOMZMKA422+5L- LZ*-G6 1S2NXW7+C-%$AO*/.EQ7 P/7 /5/7MEYLT-ZQL0N*0HY2C99-NSFFSSX02*D:NUCG0DX+ W7BFD:6/BKJQ4MVO2/$AOVVP+STHSSO7E8XVZG/O2W50ZLCM-YP66FU13Q*6P.$DYF8/ 7 G3%JDTGVD0EI13NQ7281V40-.-XC .6+37NDZ+67:2JG9YGY%PJ09SD/TFOFJ9M/X$DL%8U/36 A:K5WZ 1H1HJBLGR9S5$CG+NWW%F131I.GKK8067O8$P4:XVFJI35HH/M/5.490/ RZZXNKYHHUL/JA7O1OAJ5/:2K %IXH-PD60ELZ:8S%UJQNCT9J2.QPEZ27*V%Z.7-$F0B%QTJVJR9L50*-C/Y3I36GN66Q0SWO$J 4VPC$-3+U0E$E2XZDU6OGG.Q$LJNMWBOV1D-64AVPZGBBNWMAXXMMW1 4%-PU1:8G/T0ZV/UV6K%VB3RV006B-CC5UF/UA+RKSNML97$EC4*%3U F*+H27YD6D3G:W1WD IA%QSIXVT21*8EZFU1 :XPP3+BAMVEQYPU89I8Q:F3V VYF4T%VX8HVF1WGY+W-A1F86WMNO7$ZQBY5W% 34H4%M+WCJM9MJ957Q+S5DRPC:$SIA1A8JJ%PF5LMFRLK-3Z2XM4WP+XI3ZG2ZHE6*TGQ$%735M%R:*415YCXVJ X R0K9QMPRGCLIPC:PNK%$.U9B2RU9 +I6V%I.B1$KN*6E$WDAYEIN+7*R+QGWCKMV3RL-.D1FGFNDY-:%0.S0JES+3*VIE00WYDE%QSKPZIPTP9I:29/%VKX07-L1L$CUTZ1P3/21MBLE T/E5X.C.E/V/PDJ6++I +KL39E5ZF3OH0K3EI*2PYCHVEMIPE660/6YNHD6$S:GO-1O4 FV5BA$7 YDUWOM9F/LLQ2WI$2W4A3827.5-D$QNFQEXWWS:1LGNWD+VUB+-JJRJ3HX$82T:JR + H*U54VCF3-GRUZG:0NF%R*$-1+%V7R+5NMQ3095KR3HUL.X//ZF9G.QH%CT4WM6M%$QP+16IG ZPK2XBFZSB3PT-9.S$NWJWCZ05IQW6F09*.8K$/O98BE  5UQVR4XZRJA7KZN/W9V%5:.T$VA79$V6GQA2U.FEF3-9JFI2$55NUBR9LU2T5KTLX1AZ7A0PQYDXP+%9R2M$%+X8WC$.:B5KE6F-3O7$DZ%OVC-BJ6DCAT$IBUOJLVQZ52Y-J47VQ.EANJOW0*S$VGDGM7YJ*5S56AUH5A+M0R/CJ3G7`)
	category3GQR := []byte(`NL2:AP:TB89KNXX7H3:YELPZ*KPEBKV/MT-*P+BH271V2LWZ8T+ G7%K8R4CXDHMPDM%R*7.*9C8*KJXCPFCETI  ZT$X%PLD5 1BOHVK9GXWK/-  %5VUB1X J+XS$L%JOF47XMO8-$PL8TPR5W%G5/9G:3Z6DSV%OU$$09LUUKSD1P0.:JIHT%+E:*W:94.W0X9-0M04PG7N%UK926F3K K8R2Y HDKZTJYAHE+/X50Z/Y.J91OU*8BGF0L$22YDMZL2IAD/PX:RKRK$:8WG-K57.SOK2Z8C$FU6E5ET4Y3PZB0SF0B5BQ40-KF3J*8+FAR*DX%OQT%3CGLPHCCZ018W.CEL5/ $Z06 :ZB% TG9XKTSRDCO82YGW+/*1CR348P8GAVL.X%9Q$CKNP-33A*B5 $-HWFGJ%1-C2YY: HQM4UK20ZGM-I-G4NNA8V1.1MY KI8%4UHPK9H+VYXUX BIO0.0EKNGY2GR71:LREU%365E:104Q82E1FN+5N:M8Q-.Z O8YTJP800VHM+%818W3ZBXGD*UZ/:R6UF.$4V928G%P $ZEXDPXX1CZGCBOGC%3JH+RZT65WOSVOTSELY0P8QP8$Q2AX+XL726X.ZU/VSRXZ5JI2SO6QT735JB/:ZUWA%HPJL8N1$$JY+FFN*1LA8RS7QBBUD9/VJ.EQX2DYCK2$B65T5OT40OX9-58G% T*GWWZBC2XL:Y%YNRY:09GB9-M90:GZ5FFKGROPRZJ5I5AI%O2H/UX%X4H5VRTEZUL7OHAS00$W5W TPWO72M*IK/ZR: MQ7O-W9B7NU$1JR/7/KH5ACLO MV8HVMU%8*L.HN8J:NFPT/HUKEF3:N16Y.Z84:GBA*C:LE66*O$9D%.55XGB:WUFUK0A8O1704VB2-O2GL.$HVY/R /58: A2$BB2:3JHQK/WTE9RCB*HXANFU$8D+Q9D/E56QX5LB5SSM274O8EWQKD+IYVBJ/HLU$N1CPZFLS715LFW8RQ**ZJ.R0*%79E5C3L *I+1GKB.HD:B/QEK-NJ--WK4XU--6NV+DA6T:WG84.UU8S+K9R3H:/B%.8BLFHZ:3L*KU*PKD3ELUW/R0*0F$01E-.NBLKHKHMY+1/4CI$2QOKBP5PUE IGM*NWRY$*G.JLRGFZ7%7K5QOKC2.F8KH85867P QJ.*GW9TF%U H1/X$B*$OW*O.JTKV1FODTZB/ZT.NJ85: JO:GJW-69HRE73OFX8XLN%B3H0DV9:YOYZ79AGH*C Y5KX-:DKXYS8ZMK9H4UO00M CT3342/YHM35+LT0LY4+0X7I/%FE04R-U: `)

	testcases := []verificationPolicyTestcase{
		{categoryAbsentQR, VERIFICATION_POLICY_1G, VERIFICATION_FAILED_ERROR},
		{categoryAbsentQR, VERIFICATION_POLICY_3G, VERIFICATION_SUCCESS},
		{categoryEmptyQR, VERIFICATION_POLICY_1G, VERIFICATION_FAILED_ERROR},
		{categoryEmptyQR, VERIFICATION_POLICY_3G, VERIFICATION_SUCCESS},
		{category1GQR, VERIFICATION_POLICY_1G, VERIFICATION_SUCCESS},
		{category1GQR, VERIFICATION_POLICY_3G, VERIFICATION_SUCCESS},
		{category3GQR, VERIFICATION_POLICY_1G, VERIFICATION_FAILED_ERROR},
		{category3GQR, VERIFICATION_POLICY_3G, VERIFICATION_SUCCESS},
		{category3GQR, "2", VERIFICATION_FAILED_ERROR},
	}

	for i, testcase := range testcases {
		result := verify(testcase.qr, testcase.policy, verificationTime)
		if result.Status != testcase.expectedResult {
			t.Fatal("Unpexpected result for verification policy testcase", i, result.Error)
		}
	}
}

func TestHasDomesticPrefix(t *testing.T) {
	if !HasDomesticPrefix([]byte("NL2:")) ||
		!HasDomesticPrefix([]byte("NLZ:")) ||
		HasDomesticPrefix([]byte("NL_:")) ||
		HasDomesticPrefix([]byte("NL:")) ||
		HasDomesticPrefix([]byte("HC1:")) {
		t.Fatal("Unexpected result for HasDomesticPrefix")
	}
}

func buildCredentialsAttributes(credentialAmount int) []map[string]string {
	cas := make([]map[string]string, 0, credentialAmount)

	for i := 0; i < credentialAmount; i++ {
		validFrom := time.Now().Truncate(time.Hour).AddDate(0, 0, i-1).UTC().Unix()

		ca := map[string]string{
			"isSpecimen":       "0",
			"isPaperProof":     "0",
			"validFrom":        strconv.FormatInt(validFrom, 10),
			"validForHours":    "40",
			"firstNameInitial": "A",
			"lastNameInitial":  "R",
			"birthDay":         "20",
			"birthMonth":       "10",
			"category":         "1",
		}

		cas = append(cas, ca)
	}

	return cas
}

func attributesToVerificationDetails(attributes map[string]string) VerificationDetails {
	return VerificationDetails{
		CredentialVersion: "3",
		IsSpecimen:        attributes["isSpecimen"],
		IssuerCountryCode: "NL",

		FirstNameInitial: attributes["firstNameInitial"],
		LastNameInitial:  attributes["lastNameInitial"],
		BirthDay:         attributes["birthDay"],
		BirthMonth:       attributes["birthMonth"],
	}
}

func checkAttributesJson(attributes map[string]string, attributesJson []byte) error {
	var decodedAttributes map[string]string
	err := json.Unmarshal(attributesJson, &decodedAttributes)
	if err != nil {
		return errors.New("Error unmarshalling attributes json")
	}

	return areAttributesEqualWithCredentialVersion(attributes, decodedAttributes)
}

func areAttributesEqualWithCredentialVersion(attributes map[string]string, decodedAttributes map[string]string) error {
	if len(attributes)+1 != len(decodedAttributes) {
		return errors.New("Decoded attributes amount (with credential version) mismatch")
	}

	versionAttr, ok := decodedAttributes["credentialVersion"]
	if !ok || versionAttr != "3" {
		return errors.Errorf("Decoded credential version attribute isn't as expected")
	}

	for k, v := range attributes {
		vv, ok := decodedAttributes[k]
		if !ok || v != vv {
			return errors.New("Decoded attributes mismatch")
		}
	}

	return nil
}
