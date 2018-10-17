

package main


import "encoding/json"
import "flag"
import "fmt"
import "log"
import "os"
import "os/signal"
import "path"
import "path/filepath"
import "regexp"
import "strings"
import "syscall"
import "time"

import syslog "gopkg.in/mcuadros/go-syslog.v2"
import syslog_format "gopkg.in/mcuadros/go-syslog.v2/format"




const DefaultSyslogListenTcp = ""
const DefaultSyslogTimeoutTcp = 360 * 1000
const DefaultSyslogListenUdp = ""
const DefaultSyslogListenUnix = ""
const DefaultSyslogFormat = "rfc5424"
const DefaultSyslogQueueSize = 1024

const DefaultParserMessageJson = true

const DefaultOutputStdoutEnabled = true
const DefaultOutputStdoutJsonPretty = true
const DefaultOutputStdoutJsonSequence = false
const DefaultOutputStdoutFlush = false

const DefaultOutputFileEnabled = false
const DefaultOutputFileCurrentStorePath = ""
const DefaultOutputFileArchivedStorePath = ""
const DefaultOutputFileCurrentSymlinkPath = ""
const DefaultOutputFileCurrentPrefix = ""
const DefaultOutputFileArchivedPrefix = ""
const DefaultOutputFileCurrentSuffix = ".json-stream"
const DefaultOutputFileArchivedSuffix = ".json-stream"
const DefaultOutputFileTimestamp = "2006-01-02-15"
const DefaultOutputFileMessages = 16 * 1024
const DefaultOutputFileTimeout = 360 * time.Second
const DefaultOutputFileJsonPretty = true
const DefaultOutputFileJsonSequence = true
const DefaultOutputFileFlush = true
const DefaultOutputFileFileMode = 0640
const DefaultOutputFileStoreMode = 0750

const DefaultOutputBufferSize = 16 * 1024

const DefaultDequeueTickerTimeout = 6 * time.Second
const DefaultDequeueReportTimeout = 60 * time.Second
const DefaultDequeueReportCounter = 1000
const DefaultDequeueDebug = false
const DefaultDequeueStopTimeout = 6 * time.Second




type Message struct {
	
	Sequence uint64 `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	TimestampRaw uint64 `json:"timestamp_unix"`
	Level string `json:"level"`
	LevelRaw int8 `json:"level_unix"`
	Application string `json:"application,omitempty"`
	MessageText string `json:"message_text,omitempty"`
	MessageJson json.RawMessage `json:"message_json,omitempty"`
	Syslog map[string]interface{} `json:"syslog,omitempty"`
}



type SyslogConfiguration struct {
	
	ListenTcp string
	ListenUdp string
	ListenUnix string
	FormatName string
	FormatParser syslog_format.Format
	QueueSize uint
}


type ParserConfiguration struct {
	MessageJson bool
}


type OutputConfiguration struct {
	
	StdoutEnabled bool
	StdoutJsonPretty bool
	StdoutJsonSequence bool
	StdoutFlush bool
	
	FileEnabled bool
	FileCurrentStorePath string
	FileArchivedStorePath string
	FileCurrentSymlinkPath string
	FileCurrentPrefix string
	FileArchivedPrefix string
	FileCurrentSuffix string
	FileArchivedSuffix string
	FileTimestamp string
	FileMessages uint
	FileTimeout time.Duration
	FileJsonPretty bool
	FileJsonSequence bool
	FileFlush bool
}

type OutputContext struct {
	
	currentFileTimestamp time.Time
	currentFileTimestampToken string
	currentFileMessages uint
	currentFileCurrentPath string
	currentFileArchivedPath string
	currentFile *os.File
}


type Configuration struct {
	
	Syslog SyslogConfiguration
	Parser ParserConfiguration
	Output OutputConfiguration
}

type Context struct {
	configuration *Configuration
	output *OutputContext
}




func configure (_arguments []string) (*Configuration, error) {
	
	_flags := flag.NewFlagSet ("haproxy-logger", flag.ContinueOnError)
	
	_syslogListenTcp := _flags.String ("syslog-listen-tcp", DefaultSyslogListenTcp, "<ip>:<port>")
	_syslogListenUdp := _flags.String ("syslog-listen-udp", DefaultSyslogListenUdp, "<ip>:<port>")
	_syslogListenUnix := _flags.String ("syslog-listen-unix", DefaultSyslogListenUnix, "<path>")
	_syslogFormatName := _flags.String ("syslog-format", DefaultSyslogFormat, "rfc3164 | rfc5424")
	_syslogQueueSize := _flags.Uint ("syslog-queue", DefaultSyslogQueueSize, "<size>")
	
	_parseMessageJson := _flags.Bool ("parse-message-json", DefaultParserMessageJson, "true (*) | false")
	
	_outputStdoutEnabled := _flags.Bool ("output-stdout", DefaultOutputStdoutEnabled, "true (*) | false")
	_outputStdoutJsonPretty := _flags.Bool ("output-stdout-json-pretty", DefaultOutputStdoutJsonPretty, "true (*) | false")
	_outputStdoutJsonSequence := _flags.Bool ("output-stdout-json-sequence", DefaultOutputStdoutJsonSequence, "true | false (*)")
	_outputStdoutFlush := _flags.Bool ("output-stdout-flush", DefaultOutputStdoutFlush, "true (*) | false")
	
	_outputFileEnabled := _flags.Bool ("output-file", DefaultOutputFileEnabled, "true (*) | false")
	_outputFileCurrentStorePath := _flags.String ("output-file-current-store", DefaultOutputFileCurrentStorePath, "<path>")
	_outputFileArchivedStorePath := _flags.String ("output-file-archived-store", DefaultOutputFileArchivedStorePath, "<path>")
	_outputFileCurrentSymlinkPath := _flags.String ("output-file-current-symlink", DefaultOutputFileCurrentSymlinkPath, "<path>")
	_outputFileCurrentPrefix := _flags.String ("output-file-current-prefix", DefaultOutputFileCurrentPrefix, "<prefix>")
	_outputFileArchivedPrefix := _flags.String ("output-file-archived-prefix", DefaultOutputFileArchivedPrefix, "<prefix>")
	_outputFileCurrentSuffix := _flags.String ("output-file-current-suffix", DefaultOutputFileCurrentSuffix, "<suffix>")
	_outputFileArchivedSuffix := _flags.String ("output-file-archived-suffix", DefaultOutputFileArchivedSuffix, "<suffix>")
	_outputFileTimestamp := _flags.String ("output-file-timestamp", DefaultOutputFileTimestamp, "<format> (see https://golang.org/pkg/time/#Time.Format)")
	_outputFileMessages := _flags.Uint ("output-file-messages", DefaultOutputFileMessages, "<count>")
	_outputFileTimeout := _flags.Duration ("output-file-timeout", DefaultOutputFileTimeout, "<duration>")
	_outputFileJsonPretty := _flags.Bool ("output-file-json-pretty", DefaultOutputFileJsonPretty, "true (*) | false")
	_outputFileJsonSequence := _flags.Bool ("output-file-json-sequence", DefaultOutputFileJsonSequence, "true (*) | false")
	_outputFileFlush := _flags.Bool ("output-file-flush", DefaultOutputFileFlush, "true (*) | false")
	
	
	if error := _flags.Parse (_arguments); error != nil {
		return nil, error
	}
	
	if _flags.NArg () > 0 {
		return nil, fmt.Errorf ("[5a0e956a]  unexpected additional arguments:  `%v`", _flags.Args ())
	}
	
	
	var _syslogFormatParser syslog_format.Format = nil
	switch *_syslogFormatName {
		case "rfc3164" :
			_syslogFormatParser = syslog.RFC3164
		case "rfc5424" :
			_syslogFormatParser = syslog.RFC5424
		default :
			return nil, fmt.Errorf ("[a87e7a5f]  invalid `syslog-format` value:  `%s`", _syslogFormatParser)
	}
	
	
	if *_outputFileCurrentStorePath != "" {
		*_outputFileEnabled = true
	}
	if *_outputFileArchivedStorePath != "" {
		*_outputFileEnabled = true
	}
	
	if *_outputFileEnabled {
		if *_outputFileCurrentStorePath == "" {
			return nil, fmt.Errorf ("[4ca2fdb7]  expected `output-file-current-store`")
		}
		if *_outputFileCurrentStorePath != "" {
			if _stat, _error := os.Stat (*_outputFileCurrentStorePath); _error == nil {
				if ! _stat.IsDir () {
					return nil, fmt.Errorf ("[6b395329]  invalid `output-file-current-store` (not a folder):  `%s`", *_outputFileCurrentStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[c5fd42a7]  invalid `output-file-current-store` (does not exist):  `%s`", *_outputFileCurrentStorePath)
			} else {
				return nil, _error
			}
		}
		if *_outputFileArchivedStorePath != "" {
			if _stat, _error := os.Stat (*_outputFileArchivedStorePath); _error == nil {
				if ! _stat.IsDir () {
					return nil, fmt.Errorf ("[6b395329]  invalid `output-file-archived-store` (not a folder):  `%s`", *_outputFileArchivedStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[c5fd42a7]  invalid `output-file-archived-store` (does not exist):  `%s`", *_outputFileArchivedStorePath)
			} else {
				return nil, _error
			}
		} else {
			_outputFileArchivedStorePath = _outputFileCurrentStorePath
		}
	}
	
	_syslogConfiguration := SyslogConfiguration {
			ListenTcp : *_syslogListenTcp,
			ListenUdp : *_syslogListenUdp,
			ListenUnix : *_syslogListenUnix,
			FormatName : *_syslogFormatName,
			FormatParser : _syslogFormatParser,
			QueueSize : *_syslogQueueSize,
		}
	
	_parserConfiguration := ParserConfiguration {
			MessageJson : *_parseMessageJson,
		}
	
	_outputConfiguration := OutputConfiguration {
			
			StdoutEnabled : *_outputStdoutEnabled,
			StdoutJsonPretty : *_outputStdoutJsonPretty,
			StdoutJsonSequence : *_outputStdoutJsonSequence,
			StdoutFlush : *_outputStdoutFlush,
			
			FileEnabled : *_outputFileEnabled,
			FileCurrentStorePath : *_outputFileCurrentStorePath,
			FileArchivedStorePath : *_outputFileArchivedStorePath,
			FileCurrentSymlinkPath : *_outputFileCurrentSymlinkPath,
			FileCurrentPrefix : *_outputFileCurrentPrefix,
			FileArchivedPrefix : *_outputFileArchivedPrefix,
			FileCurrentSuffix : *_outputFileCurrentSuffix,
			FileArchivedSuffix : *_outputFileArchivedSuffix,
			FileTimestamp : *_outputFileTimestamp,
			FileMessages : *_outputFileMessages,
			FileTimeout : *_outputFileTimeout,
			FileJsonPretty : *_outputFileJsonPretty,
			FileJsonSequence : *_outputFileJsonSequence,
			FileFlush : *_outputFileFlush,
		}
	
	_configuration := & Configuration {
			Syslog : _syslogConfiguration,
			Parser : _parserConfiguration,
			Output : _outputConfiguration,
		}
	
	return _configuration, nil
}




func initializeSyslog (_configuration *SyslogConfiguration) (*syslog.Server, syslog.LogPartsChannel, error) {
	
	_queue := make (syslog.LogPartsChannel, _configuration.QueueSize)
	
	_server := syslog.NewServer ()
	
	_server.SetHandler (syslog.NewChannelHandler (_queue))
	_server.SetFormat (_configuration.FormatParser)
	_server.SetTimeout (DefaultSyslogTimeoutTcp)
	
	_listening := false
	if _configuration.ListenTcp != "" {
		log.Printf ("[42aa16d0]  syslog listening TCP on `%s`...\n", _configuration.ListenTcp)
		if _error := _server.ListenTCP (_configuration.ListenTcp); _error != nil {
			return nil, nil, _error
		}
		_listening = true
	}
	if _configuration.ListenUdp != "" {
		log.Printf ("[42aa16d0]  syslog listening UDP on `%s`...\n", _configuration.ListenUdp)
		if _error := _server.ListenUDP (_configuration.ListenUdp); _error != nil {
			return nil, nil, _error
		}
		_listening = true
	}
	if _configuration.ListenUnix != "" {
		log.Printf ("[42aa16d0]  syslog listening Unix on `%s`...\n", _configuration.ListenUnix)
		if _error := _server.ListenUnixgram (_configuration.ListenUnix); _error != nil {
			return nil, nil, _error
		}
		_listening = true
	}
	
	if !_listening {
		return nil, nil, fmt.Errorf ("[e5523f7a]  no syslog listeners configured")
	}
	
	return _server, _queue, nil
}




func dequeueLoop (_syslogQueue syslog.LogPartsChannel, _signalsQueue <-chan os.Signal, _configuration *Configuration) () {
	
	_context := & Context {
			configuration : _configuration,
			output : & OutputContext {},
		}
	
	_debug := DefaultDequeueDebug
	_ticker := time.NewTicker (DefaultDequeueTickerTimeout)
	
	var _sequence uint64 = 0
	_lastReport := time.Now ()
	
	log.Printf ("[425c288e]  dequeue started receiving messages...\n")
	
	for {
		
		if _debug {
			log.Printf ("[5cedbf0d]  dequeue waiting to receive message #%d...\n", _sequence + 1)
		}
		
		var _message syslog_format.LogParts = nil
		_shouldStop := false
		_shouldReport := false
		
		select {
			
			case _message = <- _syslogQueue :
				if _message == nil {
					_shouldStop = true
					_shouldReport = true
				}
			
			case _signal := <- _signalsQueue :
				log.Printf ("[61daa6e2]  dequeue interrupted by signal:  `%s`!\n", _signal)
				_shouldStop = true
				_shouldReport = true
			
			case <- _ticker.C :
				if _debug {
					log.Printf ("[55e14446]  dequeue timedout waiting to receive message #%d!  retrying!\n", _sequence + 1)
				}
		}
		
		_timestamp := time.Now ()
		
		if _message != nil {
			_sequence += 1
			if _error := dequeueProcess (_sequence, _message, _context); _error != nil {
				logError (_error, fmt.Sprintf ("[46d8f692]  unexpected error encountered while processing the message #%d!  ignoring!", _sequence))
			} else if _debug {
				log.Printf ("[4e4ef11d]  dequeue succeeded processing the message #%d;\n", _sequence)
			}
			if _sequence % DefaultDequeueReportCounter == 0 {
				_shouldReport = true
			}
		} else {
			if _configuration.Output.FileEnabled {
				if _error := outputFileClosePerhaps (&_configuration.Output, _context.output, _timestamp, ""); _error != nil {
					logError (_error, "")
				}
			}
		}
		
		if _timestamp.Sub (_lastReport) >= DefaultDequeueReportTimeout {
			_shouldReport = true
		}
		
		if _shouldReport {
			log.Printf ("[5cf68979]  dequeue processed %d K messages (%d);\n", _sequence / 1000, _sequence)
			_lastReport = _timestamp
		}
		
		if _shouldStop {
			break
		}
	}
	
	log.Printf ("[068b224e]  dequeue stopped receiving messages!\n")
	
	if _configuration.Output.FileEnabled {
		if _error := outputFileClose (&_configuration.Output, _context.output); _error != nil {
			logError (_error, "")
		}
	}
	
	log.Printf ("[91e9d5fb]  dequeue terminated!\n")
	os.Exit (0)
}




func dequeueStopper (_syslogQueue syslog.LogPartsChannel, _signalsQueue chan os.Signal, _configuration *Configuration) () {
	
	<- _signalsQueue
	time.Sleep (1 * time.Second)
	
	log.Printf ("[70f182e2]  dequeue stopping...\n")
	_syslogQueue <- nil
	
	time.Sleep (DefaultDequeueStopTimeout)
	log.Printf ("[44768a59]  dequeue stopping timedout!  aborting!\n")
	os.Exit (1)
}




func dequeueProcess (_sequence uint64, _syslogMessage syslog_format.LogParts, _context *Context) (error) {
	
	_configuration := _context.configuration
	
	var _message *Message
	if _message_0, _error := parse (_sequence, _syslogMessage, &_configuration.Parser); _error == nil {
		_message = _message_0
	} else {
		return _error
	}
	
	if _configuration.Output.StdoutEnabled {
		if _error := outputStdout (_message, &_configuration.Output); _error != nil {
			logError (_error, "[8533bd41]  unexpected error encountered while writing the message to stdout!  ignoring!")
		}
	}
	if _configuration.Output.FileEnabled {
		if _error := outputFile (_message, &_configuration.Output, _context.output); _error != nil {
			logError (_error, "[06b0697e]  unexpected error encountered while writing the message to file!  ignoring!")
		}
	}
	
	return nil
}




func parse (_sequence uint64, _syslogMessage syslog_format.LogParts, _configuration *ParserConfiguration) (*Message, error) {
	
	_timestamp := time.Now ()
	_timestampMilliseconds := _timestamp.UnixNano () / 1000000
	
	var _messageText string
	if _messageText_0, _messageExists := _syslogMessage["message"]; _messageExists {
		if _messageText_0, _messageIsString := _messageText_0.(string); _messageIsString {
			_messageText = _messageText_0
		} else {
			log.Printf ("[87d571ff]  syslog message #%d is missing `message` (attribute is not a string)!  ignoring!\n", _sequence)
			_messageText = ""
		}
		delete (_syslogMessage, "message")
	} else {
		log.Printf ("[6e096811]  syslog message #%d is missing `message` (attribute does not exist)!  ignoring!\n", _sequence)
		_messageText = ""
	}
	
	var _application string
	if _application_0, _applicationExists := _syslogMessage["app_name"]; _applicationExists {
		if _application_0, _applicationIsString := _application_0.(string); _applicationIsString {
			_application = _application_0
		} else {
			log.Printf ("[7cf38fac]  syslog message #%d is missing `app_name` (attribute is not a string)!  ignoring!\n", _sequence)
			_application = "<unknown>"
		}
		delete (_syslogMessage, "app_name")
	} else {
		log.Printf ("[d67aba45]  syslog message #%d is missing `app_name` (attribute does not exist)!  ignoring!\n", _sequence)
		_application = "<unknown>"
	}
	
	var _level int8
	var _levelText string
	if _severity_0, _severityExists := _syslogMessage["severity"]; _severityExists {
		switch _severity_0 {
			case 0 :
				_level = 0
				_levelText = "emergency"
			case 1 :
				_level = 1
				_levelText = "alert"
			case 2 :
				_level = 2
				_levelText = "critical"
			case 3 :
				_level = 3
				_levelText = "error"
			case 4 :
				_level = 4
				_levelText = "warning"
			case 5 :
				_level = 5
				_levelText = "notice"
			case 6 :
				_level = 6
				_levelText = "informative"
			case 7 :
				_level = 7
				_levelText = "debug"
			default :
				log.Printf ("[a11d7539]  syslog message #%d has an invalid severity `%d`!  ignoring!\n", _sequence, _severity_0)
				_level = -1
				_levelText = "<undefined>"
		}
	} else {
		log.Printf ("[aa9b6e25]  syslog message #%d is missing `severity` (attribute does not exist)!  ignoring!\n", _sequence)
		_level = -1
		_levelText = "<unknown>"
	}
	
	_messageText = strings.TrimSpace (_messageText)
	
	var _messageJson json.RawMessage = nil
	if _configuration.MessageJson {
		if strings.HasPrefix (_messageText, "{") && strings.HasSuffix (_messageText, "}") {
			if _error := json.Unmarshal ([]byte (_messageText), &_messageJson); _error == nil {
				_messageText = ""
			}
		}
	}
	
	_message := & Message {
			Sequence : _sequence,
			Timestamp : _timestamp,
			TimestampRaw : uint64 (_timestampMilliseconds),
			Level : _levelText,
			LevelRaw : _level,
			Application : _application,
			MessageText : _messageText,
			MessageJson : _messageJson,
			Syslog : _syslogMessage,
		}
	
	return _message, nil
}




func outputStdout (_message *Message, _configuration *OutputConfiguration) (error) {
	return outputStream (os.Stdout, _message, _configuration.StdoutJsonPretty, _configuration.StdoutJsonSequence, _configuration.StdoutFlush)
}




func outputFile (_message *Message, _configuration *OutputConfiguration, _context *OutputContext) (error) {
	
	_timestamp := time.Now ()
	_timestampToken := _message.Timestamp.Format (_configuration.FileTimestamp)
	
	if _error := outputFileClosePerhaps (_configuration, _context, _timestamp, _timestampToken); _error != nil {
		logError (_error, "")
	}
	if _error := outputFileOpen (_configuration, _context, _timestamp, _timestampToken); _error != nil {
		logError (_error, "")
	}
	
	_context.currentFileMessages += 1
	
	return outputStream (_context.currentFile, _message, _configuration.FileJsonPretty, _configuration.FileJsonSequence, _configuration.FileFlush)
}




func outputFileOpen (_configuration *OutputConfiguration, _context *OutputContext, _timestamp time.Time, _timestampToken string) (error) {
	
	if _context.currentFile != nil {
		return nil
	}
	
	_context.currentFileTimestamp = _timestamp
	_context.currentFileTimestampToken = _timestampToken
	_context.currentFileMessages = 0
	
	_context.currentFileCurrentPath = fmt.Sprintf (
			"%s%c%s%s-%06x-%06x%s",
			_configuration.FileCurrentStorePath,
			os.PathSeparator,
			_configuration.FileCurrentPrefix,
			_timestampToken,
			os.Getpid () & 0xffffff,
			_timestamp.Unix () & 0xffffff,
			_configuration.FileCurrentSuffix,
		)
	
	_context.currentFileArchivedPath = fmt.Sprintf (
			"%s%c%s%s-%06x-%06x%s",
			_configuration.FileArchivedStorePath,
			os.PathSeparator,
			_configuration.FileArchivedPrefix,
			_timestampToken,
			os.Getpid () & 0xffffff,
			_timestamp.Unix () & 0xffffff,
			_configuration.FileArchivedSuffix,
		)
	
	if _error := os.MkdirAll (path.Dir (_context.currentFileCurrentPath), DefaultOutputFileStoreMode); _error != nil {
		log.Printf ("[9e694a9c]  failed opening current output file to `%s` (mkdir)!  ignoring!\n", _context.currentFileCurrentPath)
		logError (_error, "")
	}
	if _file, _error := os.OpenFile (_context.currentFileCurrentPath, os.O_CREATE | os.O_EXCL | os.O_WRONLY | os.O_APPEND, DefaultOutputFileFileMode); _error == nil {
		log.Printf ("[27432827]  succeeded opening current output file `%s`;\n", _context.currentFileCurrentPath)
		_context.currentFile = _file
	} else {
		log.Printf ("[27432827]  failed opening current output file `%s` (open)!  ignoring!\n", _context.currentFileCurrentPath)
		_context.currentFile = nil
	}
	
	if _configuration.FileCurrentSymlinkPath != "" {
		if _error := os.Remove (_configuration.FileCurrentSymlinkPath); (_error != nil) && ! os.IsNotExist (_error) {
			logError (_error, "[fb4f5f7b]  failed symlink-ing current output file (unlink)!  ignoring!")
		}
		if _relativePath, _error := filepath.Rel (path.Dir (_configuration.FileCurrentSymlinkPath), _context.currentFileCurrentPath); _error != nil {
			logError (_error, "[a578ba45]  failed symlink-ing current output file (relpath)!  ignoring!")
		} else if _error := os.Symlink (_relativePath, _configuration.FileCurrentSymlinkPath); _error != nil {
			logError (_error, "[f0ccc0b5]  failed symlink-ing current output file (relpath)!  ignoring!")
		}
	}
	
	return nil
}


func outputFileClosePerhaps (_configuration *OutputConfiguration, _context *OutputContext, _timestamp time.Time, _timestampToken string) (error) {
	
	if _context.currentFile == nil {
		return nil
	}
	
	_debug := DefaultDequeueDebug
	
	_shouldClose := false
	if ! _shouldClose && (_context.currentFileMessages >= _configuration.FileMessages) {
		if _debug {
			log.Printf ("[6608f486]  current file has reached its maximum messages count limit!\n")
		}
		_shouldClose = true
	}
	if ! _shouldClose && (_timestamp.Sub (_context.currentFileTimestamp) >= _configuration.FileTimeout) {
		if _debug {
			log.Printf ("[963bf22e]  current file has reached its maximum age limit!\n")
		}
		_shouldClose = true
	}
	if ! _shouldClose && (_context.currentFileTimestampToken != _timestampToken) && (_timestampToken != "") {
		if _debug {
			log.Printf ("[214f5ea7]  current file has a different timestamp token!\n")
		}
		_shouldClose = true
	}
	
	if _shouldClose {
		return outputFileClose (_configuration, _context)
	} else {
		return nil
	}
}


func outputFileClose (_configuration *OutputConfiguration, _context *OutputContext) (error) {
	
	if _context.currentFile == nil {
		return nil
	}
	
	if _error := _context.currentFile.Close (); _error == nil {
		log.Printf ("[c1b80cc7]  succeeded closing previous output file `%s`;\n", _context.currentFileCurrentPath)
	} else {
		log.Printf ("[c1b80cc7]  failed closing previous output file `%s`!  ignoring!\n", _context.currentFileCurrentPath)
		logError (_error, "")
	}
	
	if _error := os.Remove (_configuration.FileCurrentSymlinkPath); (_error != nil) && ! os.IsNotExist (_error) {
		logError (_error, "[5df85030]  failed symlink-ing current output file (unlink)!  ignoring!")
	}
	
	if _context.currentFileCurrentPath != _context.currentFileArchivedPath {
		if _error := os.MkdirAll (path.Dir (_context.currentFileArchivedPath), DefaultOutputFileStoreMode); _error != nil {
			log.Printf ("[0febdcf9]  failed renaming previous output file to `%s` (mkdir)!  ignoring!\n", _context.currentFileArchivedPath)
			logError (_error, "")
		}
		if _error := os.Rename (_context.currentFileCurrentPath, _context.currentFileArchivedPath); _error == nil {
			log.Printf ("[04157e71]  succeeded renaming previous output file to `%s`;\n", _context.currentFileArchivedPath)
		} else {
			log.Printf ("[7ad610e7]  failed renaming previous output file to `%s` (rename)!  ignoring!\n", _context.currentFileArchivedPath)
			logError (_error, "")
		}
	}
	
	_context.currentFile = nil
	
	return nil
}



func outputStream (_stream *os.File, _message *Message, _pretty bool, _sequence bool, _flush bool) (error) {
	
	_buffer := make ([]byte, 0, DefaultOutputBufferSize)
	
	if _sequence {
		_buffer = append (_buffer, []byte ("\x1e") ...)
	} else {
		_buffer = append (_buffer, []byte ("\n\n") ...)
	}
	
	{
		var _data []byte
		var _error error
		if _pretty {
			_data, _error = json.MarshalIndent (_message, "", "\t")
		} else {
			_data, _error = json.Marshal (_message)
		}
		if _error != nil {
			return _error
		}
		_buffer = append (_buffer, _data ...)
	}
	
	if _sequence {
		_buffer = append (_buffer, []byte ("\x0a") ...)
	} else {
		_buffer = append (_buffer, []byte ("\n\n") ...)
	}
	
	if _size, _error := _stream.Write (_buffer); _error != nil {
		return _error
	} else if _size != len (_buffer) {
		return fmt.Errorf ("[82772647]  buffer written partially:  `%d` of `%d`", _size, len (_buffer))
	}
	
	if _flush {
		if _error := _stream.Sync (); _error != nil {
			return _error
		}
	}
	
	return nil
}




func main_0 () (error) {
	
	
	var _configuration *Configuration = nil
	if _configuration_0, _error := configure (os.Args[1:]); _error == nil {
		_configuration = _configuration_0
	} else {
		return _error
	}
	
	
	var _syslogServer *syslog.Server = nil
	var _syslogQueue syslog.LogPartsChannel = nil
	if _syslogServer_0, _syslogQueue_0, _error := initializeSyslog (&_configuration.Syslog); _error == nil {
		_syslogServer = _syslogServer_0
		_syslogQueue = _syslogQueue_0
	} else {
		return _error
	}
	
	_signalsQueueForLoop := make (chan os.Signal, 16)
	signal.Notify (_signalsQueueForLoop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	
	_signalsQueueForStopper := make (chan os.Signal, 16)
	signal.Notify (_signalsQueueForStopper, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	
	go dequeueLoop (_syslogQueue, _signalsQueueForLoop, _configuration)
	go dequeueStopper (_syslogQueue, _signalsQueueForStopper, _configuration)
	
	log.Printf ("[f143c879]  syslog starting...\n")
	if _error := _syslogServer.Boot (); _error != nil {
		return _error
	}
	
	_syslogServer.Wait ()
	log.Printf ("[885de1c0]  syslog stopped!\n")
	
	for {
		log.Printf ("[cd90630d]  terminating...\n")
		_signalsQueueForLoop <- syscall.SIGKILL
		_signalsQueueForStopper <- syscall.SIGKILL
		time.Sleep (1 * time.Second)
	}
	
	return nil
}


func main () () {
	
	log.SetFlags (0)
	
	if _error := main_0 (); _error == nil {
		os.Exit (0)
	} else {
		logError (_error, "")
		log.Printf ("[01ede391]  aborting!\n")
		os.Exit (1)
	}
}




func logError (_error error, _message string) () {
	
	if _message == "" {
		_message = "[906eea03]  unexpected error encountered!";
	}
	log.Printf ("%s\n", _message)
	
	_errorString := _error.Error ()
	if _matches, _matchesError := regexp.MatchString (`^\[[0-9a-f]{8}\] [^\n]+$`, _errorString); _matchesError == nil {
		if _matches {
			log.Printf ("%s\n", _errorString)
		} else {
			log.Printf ("[8a968eeb]  %q\n", _errorString)
			log.Printf ("[72c99d89]  %#v\n", _error)
		}
	} else {
		panic (_matchesError)
	}
}

