module github.com/minvws/nl-covid19-coronacheck-mobile-core

go 1.16

require (
	github.com/go-errors/errors v1.4.0
	github.com/minvws/nl-covid19-coronacheck-hcert v0.0.0-00010101000000-000000000000
	github.com/minvws/nl-covid19-coronacheck-idemix v0.1.1-0.20210524201323-7435d8be1336
	github.com/privacybydesign/gabi v0.0.0-20200823153621-467696543652
	golang.org/x/text v0.3.2
)

replace (
	github.com/minvws/base45-go v0.1.0 => github.com/confiks/base45-go v0.1.0
	github.com/minvws/nl-covid19-coronacheck-hcert => ./hcert
	github.com/minvws/nl-covid19-coronacheck-idemix => ./idemix
)
