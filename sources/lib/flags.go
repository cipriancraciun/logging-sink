

package lib


import "flag"
import "fmt"
import "os"
import "strings"

import syslog "gopkg.in/mcuadros/go-syslog.v2"
import syslog_format "gopkg.in/mcuadros/go-syslog.v2/format"




func configure (_arguments []string) (*Configuration, error) {
	
	_flags := flag.NewFlagSet ("haproxy-logger", flag.ContinueOnError)
	
	_inputSyslogEnabled := _flags.Bool ("input-syslog", DefaultInputSyslogEnabled, "true | false")
	_inputSyslogIdentifier := _flags.String ("input-syslog-identifier", DefaultInputSyslogIdentifier, "<identifier>")
	_inputSyslogListenTcp := _flags.String ("input-syslog-listen-tcp", DefaultInputSyslogListenTcp, "<ip>:<port>")
	_inputSyslogListenUdp := _flags.String ("input-syslog-listen-udp", DefaultInputSyslogListenUdp, "<ip>:<port>")
	_inputSyslogListenUnix := _flags.String ("input-syslog-listen-unix", DefaultInputSyslogListenUnix, "<path>")
	_inputSyslogFormatName := _flags.String ("input-syslog-format", DefaultInputSyslogFormat, "rfc3164 | rfc5424")
	_inputSyslogParseJson := _flags.Bool ("input-syslog-json", DefaultInputSyslogParseJson, "true | false")
	_inputSyslogParseXml := _flags.Bool ("input-syslog-xml", DefaultInputSyslogParseXml, "true | false")
	_inputSyslogDebug := _flags.Bool ("input-syslog-debug", DefaultInputSyslogDebug, "true | false")
	
	_inputHttpEnabled := _flags.Bool ("input-http", DefaultInputHttpEnabled, "true | false")
	_inputHttpIdentifier := _flags.String ("input-http-identifier", DefaultInputHttpIdentifier, "<identifier>")
	_inputHttpListenTcp := _flags.String ("input-http-listen-tcp", DefaultInputHttpListenTcp, "<ip>:<port>")
	_inputHttpAllowedPath := _flags.String ("input-http-allowed-path", DefaultInputHttpAllowedPath, "<path>")
	_inputHttpParseJson := _flags.Bool ("input-http-json", DefaultInputHttpParseJson, "true | false")
	_inputHttpParseXml := _flags.Bool ("input-http-xml", DefaultInputHttpParseXml, "true | false")
	_inputHttpDebug := _flags.Bool ("input-http-debug", DefaultInputHttpDebug, "true | false")
	
	_inputMqttEnabled := _flags.Bool ("input-mqtt", DefaultInputMqttEnabled, "true | false")
	_inputMqttIdentifier := _flags.String ("input-mqtt-identifier", DefaultInputMqttIdentifier, "<identifier>")
	_inputMqttConnectTcp := _flags.String ("input-mqtt-connect-tcp", DefaultInputMqttConnectTcp, "<ip>:<port>")
	_inputMqttTopic := _flags.String ("input-mqtt-topic", DefaultInputMqttTopic, "<topic>")
	_inputMqttClient := _flags.String ("input-mqtt-client", DefaultInputMqttClient, "<client-id>")
	_inputMqttUsername := _flags.String ("input-mqtt-username", DefaultInputMqttUsername, "<username>")
	_inputMqttPassword := _flags.String ("input-mqtt-password", DefaultInputMqttPassword, "<password>")
	_inputMqttKeepAlive := _flags.Uint ("input-mqtt-keep-alive", DefaultInputMqttKeepAlive, "<seconds>")
	_inputMqttCleanSession := _flags.Bool ("input-mqtt-clean-session", DefaultInputMqttCleanSession, "true | false")
	_inputMqttParseJson := _flags.Bool ("input-mqtt-json", DefaultInputMqttParseJson, "true | false")
	_inputMqttParseXml := _flags.Bool ("input-mqtt-xml", DefaultInputMqttParseXml, "true | false")
	_inputMqttDebug := _flags.Bool ("input-mqtt-debug", DefaultInputMqttDebug, "true | false")
	
	_outputStdoutEnabled := _flags.Bool ("output-stdout", DefaultOutputStdoutEnabled, "true | false")
	_outputStdoutJsonPretty := _flags.Bool ("output-stdout-json-pretty", DefaultOutputStdoutJsonPretty, "true | false")
	_outputStdoutJsonSequence := _flags.Bool ("output-stdout-json-sequence", DefaultOutputStdoutJsonSequence, "true | false")
	_outputStdoutFlush := _flags.Bool ("output-stdout-flush", DefaultOutputStdoutFlush, "true | false")
	_outputStdoutQueueSize := _flags.Uint ("output-stdout-queue", DefaultOutputStdoutQueueSize, "<size>")
	_outputStdoutDebug := _flags.Bool ("output-stdout-debug", DefaultOutputStdoutDebug, "true | false")
	
	_outputFileEnabled := _flags.Bool ("output-file", DefaultOutputFileEnabled, "true | false")
	_outputFileCurrentStorePath := _flags.String ("output-file-current-store", DefaultOutputFileCurrentStorePath, "<path>")
	_outputFileCurrentSymlinkPath := _flags.String ("output-file-current-symlink", DefaultOutputFileCurrentSymlinkPath, "<path>")
	_outputFileArchivedStorePath := _flags.String ("output-file-archived-store", DefaultOutputFileArchivedStorePath, "<path>")
	_outputFileArchivedCompress := _flags.String ("output-file-archived-compress", DefaultOutputFileArchivedCompress, "none | lz4 | lzo | gz | bz2 | lzip | xz | zstd")
	_outputFileArchivedCompressLevel := _flags.Uint ("output-file-archived-compress-level", DefaultOutputFileArchivedCompressLevel, "<level> (see manual for each compressor)")
	_outputFileCurrentPrefix := _flags.String ("output-file-current-prefix", DefaultOutputFileCurrentPrefix, "<prefix>")
	_outputFileArchivedPrefix := _flags.String ("output-file-archived-prefix", DefaultOutputFileArchivedPrefix, "<prefix>")
	_outputFileCurrentSuffix := _flags.String ("output-file-current-suffix", DefaultOutputFileCurrentSuffix, "<suffix>")
	_outputFileArchivedSuffix := _flags.String ("output-file-archived-suffix", DefaultOutputFileArchivedSuffix, "<suffix>")
	_outputFileCurrentTimestamp := _flags.String ("output-file-current-timestamp", DefaultOutputFileCurrentTimestamp, "<format> (see https://golang.org/pkg/time/#Time.Format)")
	_outputFileArchivedTimestamp := _flags.String ("output-file-archived-timestamp", DefaultOutputFileArchivedTimestamp, "<format> (see https://golang.org/pkg/time/#Time.Format)")
	_outputFileMessages := _flags.Uint ("output-file-messages", DefaultOutputFileMessages, "<count>")
	_outputFileTimeout := _flags.Duration ("output-file-timeout", DefaultOutputFileTimeout, "<duration>")
	_outputFileJsonPretty := _flags.Bool ("output-file-json-pretty", DefaultOutputFileJsonPretty, "true | false")
	_outputFileJsonSequence := _flags.Bool ("output-file-json-sequence", DefaultOutputFileJsonSequence, "true | false")
	_outputFileFlush := _flags.Bool ("output-file-flush", DefaultOutputFileFlush, "true | false")
	_outputFileQueueSize := _flags.Uint ("output-file-queue", DefaultOutputFileQueueSize, "<size>")
	_outputFileDebug := _flags.Bool ("output-file-debug", DefaultOutputFileDebug, "true | false")
	
	_outputMqttEnabled := _flags.Bool ("output-mqtt", DefaultOutputMqttEnabled, "true | false")
	_outputMqttIdentifier := _flags.String ("output-mqtt-identifier", DefaultOutputMqttIdentifier, "<identifier>")
	_outputMqttConnectTcp := _flags.String ("output-mqtt-connect-tcp", DefaultOutputMqttConnectTcp, "<ip>:<port>")
	_outputMqttTopic := _flags.String ("output-mqtt-topic", DefaultOutputMqttTopic, "<topic>")
	_outputMqttClient := _flags.String ("output-mqtt-client", DefaultOutputMqttClient, "<client-id>")
	_outputMqttUsername := _flags.String ("output-mqtt-username", DefaultOutputMqttUsername, "<username>")
	_outputMqttPassword := _flags.String ("output-mqtt-password", DefaultOutputMqttPassword, "<password>")
	_outputMqttKeepAlive := _flags.Uint ("output-mqtt-keep-alive", DefaultOutputMqttKeepAlive, "<seconds>")
	_outputMqttCleanSession := _flags.Bool ("output-mqtt-clean-session", DefaultOutputMqttCleanSession, "true | false")
	_outputMqttQueueSize := _flags.Uint ("output-mqtt-queue", DefaultOutputMqttQueueSize, "<size>")
	_outputMqttDebug := _flags.Bool ("output-mqtt-debug", DefaultOutputMqttDebug, "true | false")
	
	_dequeueReportInterval := _flags.Duration ("report-timeout", DefaultDequeueReportInterval, "<duration>")
	_dequeueReportCounter := _flags.Uint ("report-messages", DefaultDequeueReportCounter, "<count>")
	
	_parserMessageRaw := _flags.Bool ("parser-message-raw", DefaultParserMessageRaw, "true | false")
	_parserMessageSha256 := _flags.Bool ("parser-message-sha256", DefaultParserMessageSha256, "true | false")
	_parserExternalCommand := _flags.String ("parser-external-command", "", "<command> <argument> ...")
	_parserExternalScript := _flags.String ("parser-external-script", "", "<script>")
	_parserExternalReplace := _flags.Bool ("parser-external-replace", DefaultParserExternalReplace, "true | false")
	_parserDebug := _flags.Bool ("parser-debug", DefaultParserDebug, "true | false")
	
	_messagesQueueSize := _flags.Uint ("messages-queue", DefaultMessagesQueueSize, "<size>")
	
	_forcedDebug := _flags.Bool ("debug", false, "true | false")
	
	_globalDebug := DefaultGlobalDebug || *_forcedDebug
	
	
	if error := _flags.Parse (_arguments); error != nil {
		return nil, error
	}
	
	if _flags.NArg () > 0 {
		return nil, fmt.Errorf ("[5a0e956a]  unexpected additional arguments:  `%v`!", _flags.Args ())
	}
	
	
	var _inputSyslogConfiguration *InputSyslogConfiguration = nil
	if (*_inputSyslogListenTcp != "") || (*_inputSyslogListenUdp != "") || (*_inputSyslogListenUnix != "") {
		*_inputSyslogEnabled = true
	}
	if *_inputSyslogEnabled {
		var _inputSyslogFormatParser syslog_format.Format = nil
		switch *_inputSyslogFormatName {
			case "rfc3164" :
				_inputSyslogFormatParser = syslog.RFC3164
			case "rfc5424" :
				_inputSyslogFormatParser = syslog.RFC5424
			default :
				return nil, fmt.Errorf ("[a87e7a5f]  invalid `input-syslog-format` value:  `%s`!", *_inputSyslogFormatName)
		}
		_inputSyslogConfiguration = & InputSyslogConfiguration {
				Identifier : *_inputSyslogIdentifier,
				ListenTcp : *_inputSyslogListenTcp,
				ListenUdp : *_inputSyslogListenUdp,
				ListenUnix : *_inputSyslogListenUnix,
				Timeout : DefaultInputSyslogTimeout,
				FormatName : *_inputSyslogFormatName,
				FormatParser : _inputSyslogFormatParser,
				ParseJson : *_inputSyslogParseJson,
				ParseXml : *_inputSyslogParseXml,
				Debug : *_inputSyslogDebug || *_forcedDebug,
			}
		_globalDebug = _globalDebug || _inputSyslogConfiguration.Debug
	}
	
	
	var _inputHttpConfiguration *InputHttpConfiguration = nil
	if *_inputHttpListenTcp != "" {
		*_inputHttpEnabled = true
	}
	if *_inputHttpEnabled {
		_inputHttpConfiguration = & InputHttpConfiguration {
				Identifier : *_inputHttpIdentifier,
				ListenTcp : *_inputHttpListenTcp,
				Timeout : DefaultInputHttpTimeout,
				AllowedPath : *_inputHttpAllowedPath,
				ParseJson : *_inputHttpParseJson,
				ParseXml : *_inputHttpParseXml,
				Debug : *_inputHttpDebug || *_forcedDebug,
			}
		_globalDebug = _globalDebug || _inputHttpConfiguration.Debug
	}
	
	
	var _inputMqttConfiguration *InputMqttConfiguration = nil
	if *_inputMqttConnectTcp != "" {
		*_inputMqttEnabled = true
	}
	if *_inputMqttEnabled {
		_inputMqttConfiguration = & InputMqttConfiguration {
				Identifier : *_inputMqttIdentifier,
				ConnectTcp : *_inputMqttConnectTcp,
				Topic : *_inputMqttTopic,
				Client : *_inputMqttClient,
				Username : *_inputMqttUsername,
				Password : *_inputMqttPassword,
				KeepAlive : *_inputMqttKeepAlive,
				CleanSession : *_inputMqttCleanSession,
				ParseJson : *_inputMqttParseJson,
				ParseXml : *_inputMqttParseXml,
				Debug : *_inputMqttDebug || *_forcedDebug,
			}
		_globalDebug = _globalDebug || _inputMqttConfiguration.Debug
	}
	
	
	var _outputStdoutConfiguration *OutputStdoutConfiguration = nil
	if *_outputStdoutEnabled {
		_outputStdoutConfiguration = & OutputStdoutConfiguration {
				JsonPretty : *_outputStdoutJsonPretty,
				JsonSequence : *_outputStdoutJsonSequence,
				Flush : *_outputStdoutFlush,
				QueueSize : *_outputStdoutQueueSize,
				Debug : *_outputStdoutDebug || *_forcedDebug,
			}
		_globalDebug = _globalDebug || _outputStdoutConfiguration.Debug
	}
	
	
	var _outputFileConfiguration *OutputFileConfiguration = nil
	if (*_outputFileCurrentStorePath != "") || (*_outputFileArchivedStorePath != "") {
		*_outputFileEnabled = true
	}
	if *_outputFileEnabled {
		var _outputFileArchivedCompressCommand []string = nil
		var _outputFileArchivedCompressSuffix string = ""
		if *_outputFileCurrentStorePath == "" {
			return nil, fmt.Errorf ("[4ca2fdb7]  expected `output-file-current-store`!")
		}
		if *_outputFileCurrentStorePath != "" {
			if _stat, _error := os.Stat (*_outputFileCurrentStorePath); _error == nil {
				if ! _stat.IsDir () {
					return nil, fmt.Errorf ("[65696d6c]  invalid `output-file-current-store` (not a folder):  `%s`!", *_outputFileCurrentStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[f11abf34]  invalid `output-file-current-store` (does not exist):  `%s`!", *_outputFileCurrentStorePath)
			} else {
				return nil, _error
			}
		}
		if *_outputFileArchivedStorePath != "" {
			if _stat, _error := os.Stat (*_outputFileArchivedStorePath); _error == nil {
				if ! _stat.IsDir () {
					return nil, fmt.Errorf ("[6b395329]  invalid `output-file-archived-store` (not a folder):  `%s`!", *_outputFileArchivedStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[c5fd42a7]  invalid `output-file-archived-store` (does not exist):  `%s`!", *_outputFileArchivedStorePath)
			} else {
				return nil, _error
			}
		} else {
			_outputFileArchivedStorePath = _outputFileCurrentStorePath
		}
		_level := fmt.Sprintf ("-%d", *_outputFileArchivedCompressLevel)
		switch *_outputFileArchivedCompress {
			case "none" :
			case "lz4" :
				_outputFileArchivedCompressCommand = []string {
						"lz4", _level,
					}
				_outputFileArchivedCompressSuffix = ".lz4"
			case "lzo" :
				_outputFileArchivedCompressCommand = []string {
						"lzop", _level,
					}
				_outputFileArchivedCompressSuffix = ".lzo"
			case "gz" :
				_outputFileArchivedCompressCommand = []string {
						"gzip", _level,
					}
				_outputFileArchivedCompressSuffix = ".gz"
			case "bz2" :
				_outputFileArchivedCompressCommand = []string {
						"bzip2", _level,
					}
				_outputFileArchivedCompressSuffix = ".bz2"
			case "lzip" :
				_outputFileArchivedCompressCommand = []string {
						"lzip", _level,
					}
				_outputFileArchivedCompressSuffix = ".lz"
			case "xz" :
				_outputFileArchivedCompressCommand = []string {
						"xz", _level, "-F", "xz", "-C", "sha256", "-T", "1",
					}
				_outputFileArchivedCompressSuffix = ".xz"
			case "zstd" :
				_outputFileArchivedCompressCommand = []string {
						"zstd", _level, "-z", "-q",
					}
				_outputFileArchivedCompressSuffix = ".zst"
			default :
				return nil, fmt.Errorf ("[aa5e00d4]  invalid `output-file-archived-compress` value:  `%s`!", *_outputFileArchivedCompress)
		}
		_outputFileConfiguration = & OutputFileConfiguration {
				CurrentStorePath : *_outputFileCurrentStorePath,
				CurrentSymlinkPath : *_outputFileCurrentSymlinkPath,
				ArchivedStorePath : *_outputFileArchivedStorePath,
				ArchivedCompressCommand : _outputFileArchivedCompressCommand,
				ArchivedCompressSuffix : _outputFileArchivedCompressSuffix,
				CurrentPrefix : *_outputFileCurrentPrefix,
				ArchivedPrefix : *_outputFileArchivedPrefix,
				CurrentSuffix : *_outputFileCurrentSuffix,
				ArchivedSuffix : *_outputFileArchivedSuffix,
				CurrentTimestamp : *_outputFileCurrentTimestamp,
				ArchivedTimestamp : *_outputFileArchivedTimestamp,
				Messages : *_outputFileMessages,
				Timeout : *_outputFileTimeout,
				JsonPretty : *_outputFileJsonPretty,
				JsonSequence : *_outputFileJsonSequence,
				Flush : *_outputFileFlush,
				StoreMode : DefaultOutputFileStoreMode,
				FileMode : DefaultOutputFileFileMode,
				TickerInterval : DefaultOutputFileTickerInterval,
				QueueSize : *_outputFileQueueSize,
				Debug : *_outputFileDebug || *_forcedDebug,
			}
		_globalDebug = _globalDebug || _outputFileConfiguration.Debug
	}
	
	
	var _outputMqttConfiguration *OutputMqttConfiguration = nil
	if *_outputMqttConnectTcp != "" {
		*_outputMqttEnabled = true
	}
	if *_outputMqttEnabled {
		_outputMqttConfiguration = & OutputMqttConfiguration {
				Identifier : *_outputMqttIdentifier,
				ConnectTcp : *_outputMqttConnectTcp,
				Topic : *_outputMqttTopic,
				Client : *_outputMqttClient,
				Username : *_outputMqttUsername,
				Password : *_outputMqttPassword,
				KeepAlive : *_outputMqttKeepAlive,
				CleanSession : *_outputMqttCleanSession,
				QueueSize : *_outputMqttQueueSize,
				Debug : *_outputMqttDebug || *_forcedDebug,
			}
		_globalDebug = _globalDebug || _outputMqttConfiguration.Debug
	}
	
	
	_dequeueConfiguration := & DequeueConfiguration {
			TickerInterval : DefaultDequeueTickerInterval,
			ReportInterval : *_dequeueReportInterval,
			ReportCounter : *_dequeueReportCounter,
			Debug : DefaultDequeueDebug || *_forcedDebug,
		}
	_globalDebug = _globalDebug || _dequeueConfiguration.Debug
	
	
	var _parserExternalCommand_0 []string = nil
	if *_parserExternalCommand != "" {
		_parserExternalCommand_0 = strings.Split (strings.TrimSpace (*_parserExternalCommand), " ")
		if *_parserExternalScript != "" {
			for _argumentIndex, _argumentValue := range _parserExternalCommand_0[1:] {
				if _argumentValue == "@{script}" {
					_parserExternalCommand_0[_argumentIndex + 1] = *_parserExternalScript
				}
			}
		}
	} else if *_parserExternalScript != "" {
		_parserExternalCommand_0 = []string {
				"sh", "-c", *_parserExternalScript,
			}
	}
	
	_parserConfiguration := & ParserConfiguration {
			MessageRaw : *_parserMessageRaw,
			MessageSha256 : *_parserMessageSha256,
			ExternalCommand : _parserExternalCommand_0,
			ExternalReplace : *_parserExternalReplace,
			Debug : *_parserDebug || *_forcedDebug,
		}
	_globalDebug = _globalDebug || _parserConfiguration.Debug
	
	
	_configuration := & Configuration {
			InputSyslog : _inputSyslogConfiguration,
			InputHttp : _inputHttpConfiguration,
			InputMqtt : _inputMqttConfiguration,
			OutputStdout : _outputStdoutConfiguration,
			OutputFile : _outputFileConfiguration,
			OutputMqtt : _outputMqttConfiguration,
			Dequeue : _dequeueConfiguration,
			Parser : _parserConfiguration,
			MessagesQueueSize : *_messagesQueueSize,
			Debug : _globalDebug,
		}
	
	return _configuration, nil
}


