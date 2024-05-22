module github.com/volution/logging-sink

go 1.22

require (
	github.com/basgys/goxml2json v1.1.1-0.20231018121955-e66ee54ceaad
	github.com/jessevdk/go-flags v1.5.0
	github.com/pascaldekloe/mqtt v1.0.2
	golang.org/x/sys v0.20.0
	gopkg.in/mcuadros/go-syslog.v2 v2.3.0
)

require (
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/text v0.15.0 // indirect
)

replace gopkg.in/mcuadros/go-syslog.v2 => github.com/cipriancraciun/go-syslog-lib v0.0.0-20240522115950-5f83421d40ac
