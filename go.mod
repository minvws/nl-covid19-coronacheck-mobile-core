module github.com/minvws/nl-covid19-coronacheck-mobile-core

go 1.16

require (
	github.com/go-errors/errors v1.4.0
	github.com/minvws/nl-covid19-coronacheck-hcert v0.5.2
	github.com/minvws/nl-covid19-coronacheck-idemix v0.8.2
	github.com/privacybydesign/gabi v0.1.1-coronacheck
)

replace (
	github.com/fxamacker/cbor/v2 => github.com/confiks/cbor/v2 v2.2.1-0.20210825110544-988ba94c4f07
	github.com/privacybydesign/gabi v0.1.1-coronacheck => github.com/minvws/gabi v0.1.1-coronacheck
)
