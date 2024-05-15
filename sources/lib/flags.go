

package lib


import "encoding/json"
import "fmt"
import "os"
import "strings"
import "time"

import "github.com/jessevdk/go-flags"

import syslog "gopkg.in/mcuadros/go-syslog.v2"
import syslog_format "gopkg.in/mcuadros/go-syslog.v2/format"




func configure (_arguments []string) (*Configuration, error) {
	
	_flags := & Flags {}
	_flagsMeta := & MetaFlags {}
	
	{
		_parser := flags.NewNamedParser ("logging-sink", flags.PassDoubleDash)
		if _, _error := _parser.AddGroup ("", "", _flags); _error != nil {
			return nil, _error
		}
		if _, _error := _parser.AddGroup ("Meta options", "", _flagsMeta); _error != nil {
			return nil, _error
		}
		
		if _restArguments, _error := _parser.ParseArgs (_arguments); _error == nil {
			if len (_restArguments) > 0 {
				return nil, fmt.Errorf ("[5a0e956a]  unexpected additional arguments:  `%v`!", _restArguments)
			}
		} else {
			return nil, fmt.Errorf ("[e8668b22]  failed to parse arguments:  %s!", _error)
		}
		
		if _flagsMeta.Help {
			_parser.WriteHelp (os.Stderr)
			os.Exit (0)
		}
		if _flagsMeta.DumpFlags {
			_ini := flags.NewIniParser (_parser)
			_ini.Write (os.Stdout, flags.IniNone)
			os.Exit (0)
		}
	}
	
	_forcedDebug := flagBoolOrDefault (_flags.Global.Debug, false)
	
	_globalDebug := DefaultGlobalDebug || _forcedDebug
	
	var _inputSyslogConfiguration *InputSyslogConfiguration = nil
	if (_flags.InputSyslog != nil) && flagBoolOrDefault (_flags.InputSyslog.Enabled, DefaultInputSyslogEnabled) {
		_inputSyslogProtocol := flagStringOrDefault (_flags.InputSyslog.Protocol, DefaultInputSyslogProtocol)
		var _inputSyslogParser syslog_format.Format = nil
		switch _inputSyslogProtocol {
			case "rfc3164" :
				_inputSyslogParser = syslog.RFC3164
			case "rfc5424" :
				_inputSyslogParser = syslog.RFC5424
			default :
				return nil, fmt.Errorf ("[a87e7a5f]  invalid `input-syslog-protocol` value:  `%s`!", _inputSyslogProtocol)
		}
		_inputSyslogConfiguration = & InputSyslogConfiguration {
				Identifier : flagStringOrDefault (_flags.InputSyslog.Identifier, DefaultInputSyslogIdentifier),
				ListenTcp : flagStringOrDefault (_flags.InputSyslog.ListenTcp, DefaultInputSyslogListenTcp),
				ListenUdp : flagStringOrDefault (_flags.InputSyslog.ListenUdp, DefaultInputSyslogListenUdp),
				ListenUnix : flagStringOrDefault (_flags.InputSyslog.ListenUnix, DefaultInputSyslogListenUnix),
				Timeout : flagDurationOrDefault (_flags.InputSyslog.Timeout, DefaultInputSyslogTimeout),
				Protocol : _inputSyslogProtocol,
				Parser : _inputSyslogParser,
				ParseJson : flagBoolOrDefault (_flags.InputSyslog.ParseJson, DefaultInputSyslogParseJson),
				ParseXml : flagBoolOrDefault (_flags.InputSyslog.ParseXml, DefaultInputSyslogParseXml),
				Debug : flagBoolOrDefault (_flags.InputSyslog.Debug, DefaultInputSyslogDebug || _forcedDebug),
			}
		_globalDebug = _globalDebug || _inputSyslogConfiguration.Debug
	}
	
	var _inputHttpConfiguration *InputHttpConfiguration = nil
	if (_flags.InputHttp != nil) && flagBoolOrDefault (_flags.InputHttp.Enabled, DefaultInputHttpEnabled) {
		_inputHttpConfiguration = & InputHttpConfiguration {
				Identifier : flagStringOrDefault (_flags.InputHttp.Identifier, DefaultInputHttpIdentifier),
				ListenTcp : flagStringOrDefault (_flags.InputHttp.ListenTcp, DefaultInputHttpListenTcp),
				Timeout : flagDurationOrDefault (_flags.InputHttp.Timeout, DefaultInputHttpTimeout),
				AllowedPath : flagStringOrDefault (_flags.InputHttp.AllowedPath, DefaultInputHttpAllowedPath),
				ParseJson : flagBoolOrDefault (_flags.InputHttp.ParseJson, DefaultInputHttpParseJson),
				ParseXml : flagBoolOrDefault (_flags.InputHttp.ParseXml, DefaultInputHttpParseXml),
				Debug : flagBoolOrDefault (_flags.InputHttp.Debug, DefaultInputHttpDebug || _forcedDebug),
			}
		_globalDebug = _globalDebug || _inputHttpConfiguration.Debug
	}
	
	
	var _inputMqttConfiguration *InputMqttConfiguration = nil
	if (_flags.InputMqtt != nil) && flagBoolOrDefault (_flags.InputMqtt.Enabled, DefaultInputMqttEnabled) {
		_inputMqttConfiguration = & InputMqttConfiguration {
				Identifier : flagStringOrDefault (_flags.InputMqtt.Identifier, DefaultInputMqttIdentifier),
				ConnectTcp : flagStringOrDefault (_flags.InputMqtt.ConnectTcp, DefaultInputMqttConnectTcp),
				Topic : flagStringOrDefault (_flags.InputMqtt.Topic, DefaultInputMqttTopic),
				Client : flagStringOrDefault (_flags.InputMqtt.Client, DefaultInputMqttClient),
				Username : flagStringOrDefault (_flags.InputMqtt.Username, DefaultInputMqttUsername),
				Password : flagStringOrDefault (_flags.InputMqtt.Password, DefaultInputMqttPassword),
				CleanSession : flagBoolOrDefault (_flags.InputMqtt.CleanSession, DefaultInputMqttCleanSession),
				KeepAlive : flagDurationOrDefault (_flags.InputMqtt.KeepAlive, DefaultInputMqttKeepAlive),
				Ping : flagDurationOrDefault (_flags.InputMqtt.Ping, DefaultInputMqttPing),
				Retry : flagDurationOrDefault (_flags.InputMqtt.Retry, DefaultInputMqttRetry),
				ParseJson : flagBoolOrDefault (_flags.InputMqtt.ParseJson, DefaultInputMqttParseJson),
				ParseXml : flagBoolOrDefault (_flags.InputMqtt.ParseXml, DefaultInputMqttParseXml),
				Debug : flagBoolOrDefault (_flags.InputMqtt.Debug, DefaultInputMqttDebug) || _forcedDebug,
			}
		_globalDebug = _globalDebug || _inputMqttConfiguration.Debug
	}
	
	
	var _outputStdoutConfiguration *OutputStdoutConfiguration = nil
	if (_flags.OutputStdout != nil) && flagBoolOrDefault (_flags.OutputStdout.Enabled, DefaultOutputStdoutEnabled) {
		_outputStdoutConfiguration = & OutputStdoutConfiguration {
				BufferSize : flagUintOrDefault (_flags.OutputStdout.BufferSize, DefaultOutputStdoutBufferSize),
				JsonPretty : flagBoolOrDefault (_flags.OutputStdout.JsonPretty, DefaultOutputStdoutJsonPretty),
				JsonSequence : flagBoolOrDefault (_flags.OutputStdout.JsonSequence, DefaultOutputStdoutJsonSequence),
				Flush : flagBoolOrDefault (_flags.OutputStdout.Flush, DefaultOutputStdoutFlush),
				QueueSize : flagUintOrDefault (_flags.OutputStdout.QueueSize, DefaultOutputStdoutQueueSize),
				Debug : flagBoolOrDefault (_flags.OutputStdout.Debug, DefaultOutputStdoutDebug),
			}
		_globalDebug = _globalDebug || _outputStdoutConfiguration.Debug
	}
	
	
	var _outputFileConfiguration *OutputFileConfiguration = nil
	if (_flags.OutputFile != nil) && flagBoolOrDefault (_flags.OutputFile.Enabled, DefaultOutputFileEnabled) {
		_outputFileCurrentSymlinkPath := flagStringOrDefault (_flags.OutputFile.CurrentSymlinkPath, DefaultOutputFileCurrentSymlinkPath)
		_outputFileCurrentStorePath := flagStringOrDefault (_flags.OutputFile.CurrentStorePath, DefaultOutputFileCurrentStorePath)
		if _outputFileCurrentStorePath == "" {
			return nil, fmt.Errorf ("[4ca2fdb7]  expected `output-file-current-store`!")
		}
		if _outputFileCurrentStorePath != "" {
			if _stat, _error := os.Stat (_outputFileCurrentStorePath); _error == nil {
				if ! _stat.IsDir () {
					return nil, fmt.Errorf ("[65696d6c]  invalid `output-file-current-store` (not a folder):  `%s`!", _outputFileCurrentStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[f11abf34]  invalid `output-file-current-store` (does not exist):  `%s`!", _outputFileCurrentStorePath)
			} else {
				return nil, _error
			}
		}
		_outputFileArchivedStorePath := flagStringOrDefault (_flags.OutputFile.ArchivedStorePath, DefaultOutputFileArchivedStorePath)
		if _outputFileArchivedStorePath != "" {
			if _stat, _error := os.Stat (_outputFileArchivedStorePath); _error == nil {
				if ! _stat.IsDir () {
					return nil, fmt.Errorf ("[6b395329]  invalid `output-file-archived-store` (not a folder):  `%s`!", _outputFileArchivedStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[c5fd42a7]  invalid `output-file-archived-store` (does not exist):  `%s`!", _outputFileArchivedStorePath)
			} else {
				return nil, _error
			}
		} else {
			_outputFileArchivedStorePath = _outputFileCurrentStorePath
		}
		_outputFileArchivedCompress := flagStringOrDefault (_flags.OutputFile.ArchivedCompress, DefaultOutputFileArchivedCompress)
		_outputFileArchivedCompressLevel := flagUintOrDefault (_flags.OutputFile.ArchivedCompressLevel, DefaultOutputFileArchivedCompressLevel)
		_outputFileArchivedCompressLevelArgument := fmt.Sprintf ("-%d", _outputFileArchivedCompressLevel)
		var _outputFileArchivedCompressCommand []string = nil
		var _outputFileArchivedCompressSuffix string = ""
		switch _outputFileArchivedCompress {
			case "none" :
				break
			case "lz4" :
				_outputFileArchivedCompressCommand = []string {
						"lz4", _outputFileArchivedCompressLevelArgument,
					}
				_outputFileArchivedCompressSuffix = ".lz4"
			case "lzo" :
				_outputFileArchivedCompressCommand = []string {
						"lzop", _outputFileArchivedCompressLevelArgument,
					}
				_outputFileArchivedCompressSuffix = ".lzo"
			case "gz" :
				_outputFileArchivedCompressCommand = []string {
						"gzip", _outputFileArchivedCompressLevelArgument,
					}
				_outputFileArchivedCompressSuffix = ".gz"
			case "bz2" :
				_outputFileArchivedCompressCommand = []string {
						"bzip2", _outputFileArchivedCompressLevelArgument,
					}
				_outputFileArchivedCompressSuffix = ".bz2"
			case "lzip" :
				_outputFileArchivedCompressCommand = []string {
						"lzip", _outputFileArchivedCompressLevelArgument,
					}
				_outputFileArchivedCompressSuffix = ".lz"
			case "xz" :
				_outputFileArchivedCompressCommand = []string {
						"xz", _outputFileArchivedCompressLevelArgument, "-F", "xz", "-C", "sha256", "-T", "1",
					}
				_outputFileArchivedCompressSuffix = ".xz"
			case "zstd" :
				_outputFileArchivedCompressCommand = []string {
						"zstd", _outputFileArchivedCompressLevelArgument, "-z", "-q",
					}
				_outputFileArchivedCompressSuffix = ".zst"
			default :
				return nil, fmt.Errorf ("[aa5e00d4]  invalid `output-file-archived-compress` value:  `%s`!", _outputFileArchivedCompress)
		}
		_outputFileConfiguration = & OutputFileConfiguration {
				CurrentStorePath : _outputFileCurrentStorePath,
				CurrentSymlinkPath : _outputFileCurrentSymlinkPath,
				ArchivedStorePath : _outputFileArchivedStorePath,
				ArchivedCompressCommand : _outputFileArchivedCompressCommand,
				ArchivedCompressSuffix : _outputFileArchivedCompressSuffix,
				CurrentPrefix : flagStringOrDefault (_flags.OutputFile.CurrentPrefix, DefaultOutputFileCurrentPrefix),
				ArchivedPrefix : flagStringOrDefault (_flags.OutputFile.ArchivedPrefix, DefaultOutputFileArchivedPrefix),
				CurrentSuffix : flagStringOrDefault (_flags.OutputFile.CurrentSuffix, DefaultOutputFileCurrentSuffix),
				ArchivedSuffix : flagStringOrDefault (_flags.OutputFile.ArchivedSuffix, DefaultOutputFileArchivedSuffix),
				CurrentTimestamp : flagStringOrDefault (_flags.OutputFile.CurrentTimestamp, DefaultOutputFileCurrentTimestamp),
				ArchivedTimestamp : flagStringOrDefault (_flags.OutputFile.ArchivedTimestamp, DefaultOutputFileArchivedTimestamp),
				RotateInterval : flagDurationOrDefault (_flags.OutputFile.RotateInterval, DefaultOutputFileRotateInterval),
				RotateCounter : flagUintOrDefault (_flags.OutputFile.RotateCounter, DefaultOutputFileRotateCounter),
				FolderMode : os.FileMode (flagUint16OrDefault (_flags.OutputFile.FolderMode, DefaultOutputFileFolderMode) & 0777),
				FileMode : os.FileMode (flagUint16OrDefault (_flags.OutputFile.FileMode, DefaultOutputFileFileMode) & 0777),
				BufferSize : flagUintOrDefault (_flags.OutputFile.BufferSize, DefaultOutputFileBufferSize),
				JsonPretty : flagBoolOrDefault (_flags.OutputFile.JsonPretty, DefaultOutputFileJsonPretty),
				JsonSequence : flagBoolOrDefault (_flags.OutputFile.JsonSequence, DefaultOutputFileJsonSequence),
				Flush : flagBoolOrDefault (_flags.OutputFile.Flush, DefaultOutputFileFlush),
				QueueSize : flagUintOrDefault (_flags.OutputFile.QueueSize, DefaultOutputFileQueueSize),
				Debug : flagBoolOrDefault (_flags.OutputFile.Debug, DefaultOutputFileDebug),
				TickerInterval : DefaultOutputFileTickerInterval,
			}
		_globalDebug = _globalDebug || _outputFileConfiguration.Debug
	}
	
	
	var _outputMqttConfiguration *OutputMqttConfiguration = nil
	if (_flags.OutputMqtt != nil) && flagBoolOrDefault (_flags.OutputMqtt.Enabled, DefaultOutputMqttEnabled) {
		_outputMqttConfiguration = & OutputMqttConfiguration {
				Identifier : flagStringOrDefault (_flags.OutputMqtt.Identifier, DefaultOutputMqttIdentifier),
				ConnectTcp : flagStringOrDefault (_flags.OutputMqtt.ConnectTcp, DefaultOutputMqttConnectTcp),
				Topic : flagStringOrDefault (_flags.OutputMqtt.Topic, DefaultOutputMqttTopic),
				TopicSuffix : flagStringOrDefault (_flags.OutputMqtt.TopicSuffix, DefaultOutputMqttTopicSuffix),
				Client : flagStringOrDefault (_flags.OutputMqtt.Client, DefaultOutputMqttClient),
				Username : flagStringOrDefault (_flags.OutputMqtt.Username, DefaultOutputMqttUsername),
				Password : flagStringOrDefault (_flags.OutputMqtt.Password, DefaultOutputMqttPassword),
				CleanSession : flagBoolOrDefault (_flags.OutputMqtt.CleanSession, DefaultOutputMqttCleanSession),
				KeepAlive : flagDurationOrDefault (_flags.OutputMqtt.KeepAlive, DefaultOutputMqttKeepAlive),
				Ping : flagDurationOrDefault (_flags.OutputMqtt.Ping, DefaultOutputMqttPing),
				Retry : flagDurationOrDefault (_flags.OutputMqtt.Retry, DefaultOutputMqttRetry),
				QueueSize : flagUintOrDefault (_flags.OutputMqtt.QueueSize, DefaultOutputMqttQueueSize),
				Debug : flagBoolOrDefault (_flags.OutputMqtt.Debug, DefaultOutputMqttDebug) || _forcedDebug,
			}
		_globalDebug = _globalDebug || _outputMqttConfiguration.Debug
	}
	
	var _dequeueConfiguration *DequeueConfiguration = nil
	if _flags.Dequeue == nil {
		_flags.Dequeue = & DequeueFlags {}
	}
	{
		_dequeueConfiguration = & DequeueConfiguration {
				ReportInterval : flagDurationOrDefault (_flags.Dequeue.ReportInterval, DefaultDequeueReportInterval),
				ReportCounter : flagUintOrDefault (_flags.Dequeue.ReportCounter, DefaultDequeueReportCounter),
				Debug : flagBoolOrDefault (_flags.Dequeue.Debug, DefaultDequeueDebug) || _forcedDebug,
				TickerInterval : DefaultDequeueTickerInterval,
			}
		_globalDebug = _globalDebug || _dequeueConfiguration.Debug
	}
	
	
	var _parserConfiguration *ParserConfiguration
	if _flags.Parser == nil {
		_flags.Parser = & ParserFlags {}
	}
	{
		_parserExternalCommand_0 := flagStringOrDefault (_flags.Parser.ExternalCommand, "")
		_parserExternalScript := flagStringOrDefault (_flags.Parser.ExternalScript, "")
		var _parserExternalCommand []string = nil
		if _parserExternalCommand_0 != "" {
			_parserExternalCommand = strings.Split (strings.TrimSpace (_parserExternalCommand_0), " ")
			if _parserExternalScript != "" {
				for _argumentIndex, _argumentValue := range _parserExternalCommand[1:] {
					if _argumentValue == "@{script}" {
						_parserExternalCommand[_argumentIndex + 1] = _parserExternalScript
					}
				}
			}
		} else if _parserExternalScript != "" {
			_parserExternalCommand = []string {
					"sh", "-c", _parserExternalScript,
				}
		}
		_parserConfiguration = & ParserConfiguration {
				MessageRaw : flagBoolOrDefault (_flags.Parser.MessageRaw, DefaultParserMessageRaw),
				MessageSha256 : flagBoolOrDefault (_flags.Parser.MessageSha256, DefaultParserMessageSha256),
				ExternalCommand : _parserExternalCommand,
				ExternalReplace : flagBoolOrDefault (_flags.Parser.ExternalReplace, DefaultParserExternalReplace),
				Debug : flagBoolOrDefault (_flags.Parser.Debug, DefaultParserDebug || _forcedDebug),
			}
		_globalDebug = _globalDebug || _parserConfiguration.Debug
	}
	
	
	_configuration := & Configuration {
			InputSyslog : _inputSyslogConfiguration,
			InputHttp : _inputHttpConfiguration,
			InputMqtt : _inputMqttConfiguration,
			OutputStdout : _outputStdoutConfiguration,
			OutputFile : _outputFileConfiguration,
			OutputMqtt : _outputMqttConfiguration,
			Dequeue : _dequeueConfiguration,
			Parser : _parserConfiguration,
			MessagesQueueSize : flagUintOrDefault (_flags.Dequeue.MessagesQueueSize, DefaultMessagesQueueSize),
			Debug : _globalDebug,
		}
	
	if _flagsMeta.DumpConfiguration {
		_encoder := json.NewEncoder (os.Stdout)
		_encoder.SetIndent ("", "    ")
		if _error := _encoder.Encode (_configuration); _error != nil {
			return nil, _error
		}
		os.Exit (0)
	}
	
	return _configuration, nil
}




func flagBoolOrDefault (_value *FlagsBool, _default bool) (bool) {
	if _value != nil {
		return bool (*_value)
	}
	return _default
}

func flagUintOrDefault (_value *uint, _default uint) (uint) {
	if _value != nil {
		return *_value
	}
	return _default
}

func flagUint16OrDefault (_value *uint16, _default uint16) (uint16) {
	if _value != nil {
		return *_value
	}
	return _default
}

func flagStringOrDefault (_value *string, _default string) (string) {
	if _value != nil {
		return *_value
	}
	return _default
}

func flagDurationOrDefault (_value *time.Duration, _default time.Duration) (time.Duration) {
	if _value != nil {
		return *_value
	}
	return _default
}

func flagStringsOrDefault (_value *[]string, _default []string) ([]string) {
	if _value != nil {
		return *_value
	}
	return _default
}




type FlagsBool bool
func (_bool *FlagsBool) UnmarshalFlag (_value string) (error) {
	switch _value {
		case "true", "t", "yes", "y" :
			*_bool = true
			return nil
		case "false", "f", "no", "n" :
			*_bool = false
			return nil
		default :
			return fmt.Errorf("[96e0db00]  invalid flag value:  `%s`!", _value)
	}
}

func (_bool FlagsBool) MarshalFlag () (string) {
	if _bool {
		return "true"
	} else {
		return "false"
	}
}

