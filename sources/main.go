

package main


import "encoding/json"
import "flag"
import "fmt"
import "log"
import "os"
import "os/exec"
import "os/signal"
import "path"
import "path/filepath"
import "regexp"
import "strings"
import "sync"
import "syscall"
import "time"

import syslog "gopkg.in/mcuadros/go-syslog.v2"
import syslog_format "gopkg.in/mcuadros/go-syslog.v2/format"




const DefaultInputSyslogEnabled = false
const DefaultInputSyslogListenTcp = ""
const DefaultInputSyslogTimeoutTcp = 360 * 1000
const DefaultInputSyslogListenUdp = ""
const DefaultInputSyslogListenUnix = ""
const DefaultInputSyslogFormat = "rfc5424"
const DefaultInputSyslogQueueSize = 1024
const DefaultInputSyslogDebug = false

const DefaultOutputStdoutEnabled = true
const DefaultOutputStdoutJsonPretty = true
const DefaultOutputStdoutJsonSequence = false
const DefaultOutputStdoutFlush = false
const DefaultOutputStdoutQueueSize = 1024

const DefaultOutputFileEnabled = false
const DefaultOutputFileCurrentStorePath = ""
const DefaultOutputFileCurrentSymlinkPath = ""
const DefaultOutputFileArchivedStorePath = ""
const DefaultOutputFileArchivedCompress = ""
const DefaultOutputFileCurrentPrefix = ""
const DefaultOutputFileArchivedPrefix = ""
const DefaultOutputFileCurrentSuffix = ".json-stream"
const DefaultOutputFileArchivedSuffix = ".json-stream"
const DefaultOutputFileCurrentTimestamp = "2006-01-02-15"
const DefaultOutputFileArchivedTimestamp = "2006-01/2006-01-02-15"
const DefaultOutputFileMessages = 16 * 1024
const DefaultOutputFileTimeout = 360 * time.Second
const DefaultOutputFileJsonPretty = true
const DefaultOutputFileJsonSequence = true
const DefaultOutputFileFlush = true
const DefaultOutputFileStoreMode = 0750
const DefaultOutputFileFileMode = 0640
const DefaultOutputFileTickerInterval = 6 * time.Second
const DefaultOutputFileQueueSize = 1024
const DefaultOutputFileDebug = false

const DefaultOutputBufferSize = 16 * 1024

const DefaultParserMessageJson = true

const DefaultDequeueTickerInterval = 6 * time.Second
const DefaultDequeueReportInterval = 60 * time.Second
const DefaultDequeueReportCounter = 1000
const DefaultDequeueDebug = false

const DefaultSignalsQueueSize = 16




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




type InputSyslogConfiguration struct {
	
	ListenTcp string
	TimeoutTcp uint
	ListenUdp string
	ListenUnix string
	FormatName string
	FormatParser syslog_format.Format
	QueueSize uint
}

type InputSyslogContext struct {
	
	configuration *InputSyslogConfiguration
	initialized bool
	
	server *syslog.Server
	
	syslogQueue chan<- syslog_format.LogParts
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




type OutputStdoutConfiguration struct {
	
	JsonPretty bool
	JsonSequence bool
	Flush bool
	QueueSize uint
}

type OutputStdoutContext struct {
	
	configuration *OutputStdoutConfiguration
	initialized bool
	
	file *os.File
	
	messagesQueue <-chan *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




type OutputFileConfiguration struct {
	
	CurrentStorePath string
	CurrentSymlinkPath string
	ArchivedStorePath string
	ArchivedCompressCommand []string
	ArchivedCompressSuffix string
	CurrentPrefix string
	ArchivedPrefix string
	CurrentSuffix string
	ArchivedSuffix string
	CurrentTimestamp string
	ArchivedTimestamp string
	Messages uint
	Timeout time.Duration
	JsonPretty bool
	JsonSequence bool
	Flush bool
	StoreMode os.FileMode
	FileMode os.FileMode
	Debug bool
	TickerInterval time.Duration
	QueueSize uint
}

type OutputFileContext struct {
	
	configuration *OutputFileConfiguration
	initialized bool
	
	nowTimestamp time.Time
	nowTimestampToken string
	
	currentTimestamp time.Time
	currentTimestampToken string
	currentMessages uint
	currentCurrentPath string
	currentArchivedPath string
	currentFile *os.File
	
	messagesQueue <-chan *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




type DequeueConfiguration struct {
	
	TickerInterval time.Duration
	ReportInterval time.Duration
	ReportCounter uint
	Debug bool
}

type DequeueContext struct {
	
	configuration *DequeueConfiguration
	parser *ParserContext
	initialized bool
	
	sequence uint64
	
	syslogQueue <-chan syslog_format.LogParts
	outboundQueues [] chan<- *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




type ParserConfiguration struct {
	
	MessageJson bool
}

type ParserContext struct {
	
	configuration *ParserConfiguration
	initialized bool
}




type Configuration struct {
	
	InputSyslog *InputSyslogConfiguration
	OutputStdout *OutputStdoutConfiguration
	OutputFile *OutputFileConfiguration
	Dequeue *DequeueConfiguration
	Parser *ParserConfiguration
}




func configure (_arguments []string) (*Configuration, error) {
	
	_flags := flag.NewFlagSet ("haproxy-logger", flag.ContinueOnError)
	
	_inputSyslogEnabled := _flags.Bool ("input-syslog", DefaultInputSyslogEnabled, "true (*) | false")
	_inputSyslogListenTcp := _flags.String ("input-syslog-listen-tcp", DefaultInputSyslogListenTcp, "<ip>:<port>")
	_inputSyslogListenUdp := _flags.String ("input-syslog-listen-udp", DefaultInputSyslogListenUdp, "<ip>:<port>")
	_inputSyslogListenUnix := _flags.String ("input-syslog-listen-unix", DefaultInputSyslogListenUnix, "<path>")
	_inputSyslogFormatName := _flags.String ("input-syslog-format", DefaultInputSyslogFormat, "rfc3164 | rfc5424")
	_inputSyslogQueueSize := _flags.Uint ("input-syslog-queue", DefaultInputSyslogQueueSize, "<size>")
	
	_outputStdoutEnabled := _flags.Bool ("output-stdout", DefaultOutputStdoutEnabled, "true (*) | false")
	_outputStdoutJsonPretty := _flags.Bool ("output-stdout-json-pretty", DefaultOutputStdoutJsonPretty, "true (*) | false")
	_outputStdoutJsonSequence := _flags.Bool ("output-stdout-json-sequence", DefaultOutputStdoutJsonSequence, "true | false (*)")
	_outputStdoutFlush := _flags.Bool ("output-stdout-flush", DefaultOutputStdoutFlush, "true (*) | false")
	_outputStdoutQueueSize := _flags.Uint ("output-stdout-queue", DefaultOutputStdoutQueueSize, "<size>")
	
	_outputFileEnabled := _flags.Bool ("output-file", DefaultOutputFileEnabled, "true (*) | false")
	_outputFileCurrentStorePath := _flags.String ("output-file-current-store", DefaultOutputFileCurrentStorePath, "<path>")
	_outputFileCurrentSymlinkPath := _flags.String ("output-file-current-symlink", DefaultOutputFileCurrentSymlinkPath, "<path>")
	_outputFileArchivedStorePath := _flags.String ("output-file-archived-store", DefaultOutputFileArchivedStorePath, "<path>")
	_outputFileArchivedCompress := _flags.String ("output-file-archived-compress", DefaultOutputFileArchivedCompress, "none | lz4 | lzo | gz | bz2 | xz")
	_outputFileCurrentPrefix := _flags.String ("output-file-current-prefix", DefaultOutputFileCurrentPrefix, "<prefix>")
	_outputFileArchivedPrefix := _flags.String ("output-file-archived-prefix", DefaultOutputFileArchivedPrefix, "<prefix>")
	_outputFileCurrentSuffix := _flags.String ("output-file-current-suffix", DefaultOutputFileCurrentSuffix, "<suffix>")
	_outputFileArchivedSuffix := _flags.String ("output-file-archived-suffix", DefaultOutputFileArchivedSuffix, "<suffix>")
	_outputFileCurrentTimestamp := _flags.String ("output-file-current-timestamp", DefaultOutputFileCurrentTimestamp, "<format> (see https://golang.org/pkg/time/#Time.Format)")
	_outputFileArchivedTimestamp := _flags.String ("output-file-archived-timestamp", DefaultOutputFileArchivedTimestamp, "<format> (see https://golang.org/pkg/time/#Time.Format)")
	_outputFileMessages := _flags.Uint ("output-file-messages", DefaultOutputFileMessages, "<count>")
	_outputFileTimeout := _flags.Duration ("output-file-timeout", DefaultOutputFileTimeout, "<duration>")
	_outputFileJsonPretty := _flags.Bool ("output-file-json-pretty", DefaultOutputFileJsonPretty, "true (*) | false")
	_outputFileJsonSequence := _flags.Bool ("output-file-json-sequence", DefaultOutputFileJsonSequence, "true (*) | false")
	_outputFileFlush := _flags.Bool ("output-file-flush", DefaultOutputFileFlush, "true (*) | false")
	_outputFileQueueSize := _flags.Uint ("output-file-queue", DefaultOutputFileQueueSize, "<size>")
	
	_parseMessageJson := _flags.Bool ("parse-message-json", DefaultParserMessageJson, "true (*) | false")
	
	
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
				return nil, fmt.Errorf ("[a87e7a5f]  invalid `syslog-format` value:  `%s`!", *_inputSyslogFormatName)
		}
		_inputSyslogConfiguration = & InputSyslogConfiguration {
				ListenTcp : *_inputSyslogListenTcp,
				TimeoutTcp : DefaultInputSyslogTimeoutTcp,
				ListenUdp : *_inputSyslogListenUdp,
				ListenUnix : *_inputSyslogListenUnix,
				FormatName : *_inputSyslogFormatName,
				FormatParser : _inputSyslogFormatParser,
				QueueSize : *_inputSyslogQueueSize,
			}
	}
	
	
	var _outputStdoutConfiguration *OutputStdoutConfiguration = nil
	if *_outputStdoutEnabled {
		_outputStdoutConfiguration = & OutputStdoutConfiguration {
				JsonPretty : *_outputStdoutJsonPretty,
				JsonSequence : *_outputStdoutJsonSequence,
				Flush : *_outputStdoutFlush,
				QueueSize : *_outputStdoutQueueSize,
			}
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
					return nil, fmt.Errorf ("[6b395329]  invalid `output-file-current-store` (not a folder):  `%s`!", *_outputFileCurrentStorePath)
				}
			} else if os.IsNotExist (_error) {
				return nil, fmt.Errorf ("[c5fd42a7]  invalid `output-file-current-store` (does not exist):  `%s`!", *_outputFileCurrentStorePath)
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
		switch *_outputFileArchivedCompress {
			case "none" :
			case "lz4" :
				_outputFileArchivedCompressCommand = []string {
						"lz4", "-1",
					}
				_outputFileArchivedCompressSuffix = ".lz4"
			case "lzo" :
				_outputFileArchivedCompressCommand = []string {
						"lzop", "-1",
					}
				_outputFileArchivedCompressSuffix = ".lzo"
			case "gz" :
				_outputFileArchivedCompressCommand = []string {
						"gzip", "-1",
					}
				_outputFileArchivedCompressSuffix = ".gz"
			case "bz2" :
				_outputFileArchivedCompressCommand = []string {
						"bzip2", "-1",
					}
				_outputFileArchivedCompressSuffix = ".bz2"
			case "xz" :
				_outputFileArchivedCompressCommand = []string {
						"xz", "-1", "-F", "xz", "-C", "sha256", "-T", "1",
					}
				_outputFileArchivedCompressSuffix = ".xz"
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
				Debug : DefaultOutputFileDebug,
			}
	}
	
	
	_dequeueConfiguration := & DequeueConfiguration {
			TickerInterval : DefaultDequeueTickerInterval,
			ReportInterval : DefaultDequeueReportInterval,
			ReportCounter : DefaultDequeueReportCounter,
			Debug : DefaultDequeueDebug,
		}
	
	_parserConfiguration := & ParserConfiguration {
			MessageJson : *_parseMessageJson,
		}
	
	
	_configuration := & Configuration {
			InputSyslog : _inputSyslogConfiguration,
			OutputStdout : _outputStdoutConfiguration,
			OutputFile : _outputFileConfiguration,
			Dequeue : _dequeueConfiguration,
			Parser : _parserConfiguration,
		}
	
	return _configuration, nil
}




func inputSyslogInitialize (_configuration *InputSyslogConfiguration, _syslogQueue chan<- syslog_format.LogParts, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*InputSyslogContext, error) {
	
	_server := syslog.NewServer ()
	
	_server.SetHandler (InputSyslogHandler (_syslogQueue))
	_server.SetFormat (_configuration.FormatParser)
	_server.SetTimeout (int64 (_configuration.TimeoutTcp))
	
	_listening := false
	if _configuration.ListenTcp != "" {
		log.Printf ("[42aa16d0]  input syslog listening TCP on `%s`...\n", _configuration.ListenTcp)
		if _error := _server.ListenTCP (_configuration.ListenTcp); _error != nil {
			_server.Kill ()
			return nil, _error
		}
		_listening = true
	}
	if _configuration.ListenUdp != "" {
		log.Printf ("[42aa16d0]  input syslog listening UDP on `%s`...\n", _configuration.ListenUdp)
		if _error := _server.ListenUDP (_configuration.ListenUdp); _error != nil {
			_server.Kill ()
			return nil, _error
		}
		_listening = true
	}
	if _configuration.ListenUnix != "" {
		log.Printf ("[42aa16d0]  input syslog listening Unix on `%s`...\n", _configuration.ListenUnix)
		if _error := _server.ListenUnixgram (_configuration.ListenUnix); _error != nil {
			_server.Kill ()
			return nil, _error
		}
		_listening = true
	}
	
	if !_listening {
		_server.Kill ()
		return nil, fmt.Errorf ("[e5523f7a]  input syslog has no listeners configured!")
	}
	
	log.Printf ("[f143c879]  input syslog starting...\n")
	
	if _error := _server.Boot (); _error != nil {
		return nil, _error
	}
	
	_context := & InputSyslogContext {
			configuration : _configuration,
			initialized : true,
			server : _server,
			syslogQueue : _syslogQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	_exitGroup.Add (1)
	
	go inputSyslogLooper (_context)
	
	return _context, nil
}


func inputSyslogFinalize (_context *InputSyslogContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	var _error error = nil
	if _context.server != nil {
		_error = _context.server.Kill ()
	}
	
	_exitGroup := _context.exitGroup
	
	_context.server = nil
	_context.syslogQueue = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	_context.initialized = false
	
	_exitGroup.Done ()
	
	return _error
}


func inputSyslogLooper (_context *InputSyslogContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	log.Printf ("[58bc4187]  input syslog started;\n")
	
	_stop : for {
		select {
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						log.Printf ("[56ebeed8]  input syslog interrupted by signal:  `%s`!  terminating!\n", _signal)
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[56ebeed8]  input syslog interrupted by unexpected signal:  `%s`!  ignoring!\n", _signal)
				}
		}
	}
	
	log.Printf ("[22397366]  input syslog finalizing...\n")
	if _error := inputSyslogFinalize (_context); _error != nil {
		logError (_error, "[0d40d40b]  input syslog failed to finalize!  ignoring!")
		return _error
	}
	
	log.Printf ("[50f377f5]  input syslog terminated;\n")
	return nil
}


type InputSyslogHandler chan<- syslog_format.LogParts

func (_syslogQueue InputSyslogHandler) Handle (_message syslog_format.LogParts, _ int64, _error error) () {
	if _error == nil {
		_syslogQueue <- _message
	} else {
		logError (_error, "")
	}
}




func dequeueInitialize (_configuration *DequeueConfiguration, _parser *ParserContext, _syslogQueue <-chan syslog_format.LogParts, _outboundQueues [] chan<- *Message, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*DequeueContext, error) {
	
	_context := & DequeueContext {
			configuration : _configuration,
			parser : _parser,
			initialized : true,
			syslogQueue : _syslogQueue,
			outboundQueues : _outboundQueues,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	log.Printf ("[e686224a]  dequeue starting...\n")
	
	_exitGroup.Add (1)
	
	go dequeueLooper (_context)
	
	return _context, nil
}


func dequeueFinalize (_context *DequeueContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_exitGroup := _context.exitGroup
	
	_context.initialized = false
	_context.syslogQueue = nil
	_context.outboundQueues = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	
	parserFinalize (_context.parser)
	
	_exitGroup.Done ()
	
	return nil
}


func dequeueLooper (_context *DequeueContext) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[2db95b48]  dequeue is not initialized!")
	}
	
	_configuration := _context.configuration
	_ticker := time.NewTicker (_configuration.TickerInterval)
	
	_lastReport := time.Now ()
	
	log.Printf ("[425c288e]  dequeue started receiving messages...\n")
	
	for {
		
		if _configuration.Debug {
			log.Printf ("[5cedbf0d]  dequeue waiting to receive message #%d...\n", _context.sequence + 1)
		}
		
		var _message syslog_format.LogParts = nil
		_shouldStop := false
		_shouldReport := false
		
		select {
			
			case _message = <- _context.syslogQueue :
				if _message == nil {
					_shouldStop = true
					_shouldReport = true
				}
			
			case _signal := <- _context.signalsQueue :
				log.Printf ("[61daa6e2]  dequeue interrupted by signal:  `%s`!\n", _signal)
				_shouldStop = true
				_shouldReport = true
			
			case <- _ticker.C :
				if _configuration.Debug {
					log.Printf ("[55e14446]  dequeue timedout waiting to receive message #%d;  retrying!\n", _context.sequence + 1)
				}
		}
		
		_timestamp := time.Now ()
		
		if _message != nil {
			_context.sequence += 1
			if _error := dequeueProcess (_context, _message); _error != nil {
				logError (_error, fmt.Sprintf ("[46d8f692]  unexpected error encountered while processing the message #%d!  ignoring!", _context.sequence))
			} else if _configuration.Debug {
				log.Printf ("[4e4ef11d]  dequeue succeeded processing the message #%d;\n", _context.sequence)
			}
			if (_context.sequence % uint64 (_configuration.ReportCounter)) == 0 {
				_shouldReport = true
			}
		}
		
		if _timestamp.Sub (_lastReport) >= _configuration.ReportInterval {
			_shouldReport = true
		}
		
		if _shouldReport {
			log.Printf ("[5cf68979]  dequeue processed %d K messages (%d);\n", _context.sequence / 1000, _context.sequence)
			_lastReport = _timestamp
		}
		
		if _shouldStop {
			break
		}
	}
	
	log.Printf ("[068b224e]  dequeue stopped receiving messages;\n")
	
	log.Printf ("[d39d8157]  dequeue finalizing...\n")
	if _error := dequeueFinalize (_context); _error != nil {
		logError (_error, "[b31a98f6]  dequeue failed to finalize!  ignoring!\n")
		return _error
	}
	
	log.Printf ("[c3dabaf5]  dequeue terminated;\n")
	return nil
}


func dequeueProcess (_context *DequeueContext, _syslogMessage syslog_format.LogParts) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[1740da8a]  dequeue is not initialized!")
	}
	
	// _configuration := _context.configuration
	
	var _message *Message
	if _message_0, _error := parserProcess (_context.parser, _syslogMessage, _context.sequence); _error == nil {
		_message = _message_0
	} else {
		return _error
	}
	
	for _, _outboundQueue := range _context.outboundQueues {
		select {
			case _outboundQueue <- _message :
		}
	}
	
	return nil
}




func parserInitialize (_configuration *ParserConfiguration) (*ParserContext, error) {
	
	_context := & ParserContext {
			configuration : _configuration,
			initialized : true,
		}
	
	return _context, nil
}


func parserFinalize (_context *ParserContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_context.initialized = false
	
	return nil
}


func parserProcess (_context *ParserContext, _syslogMessage syslog_format.LogParts, _sequence uint64) (*Message, error) {
	
	if ! _context.initialized {
		return nil, fmt.Errorf ("[6572b28d]  parser is not initialized!")
	}
	
	_configuration := _context.configuration
	
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




func outputStdoutInitialize (_configuration *OutputStdoutConfiguration, _messagesQueue <-chan *Message, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*OutputStdoutContext, error) {
	
	_context := & OutputStdoutContext {
			configuration : _configuration,
			initialized : true,
			file : os.Stdout,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	log.Printf ("[f168ffc9]  output stdout starting...\n")
	
	_exitGroup.Add (1)
	
	go outputStdoutLooper (_context)
	
	return _context, nil
}


func outputStdoutFinalize (_context *OutputStdoutContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	var _error error = nil
	if _context.file != nil {
		_error = _context.file.Close ()
	}
	
	_exitGroup := _context.exitGroup
	
	_context.initialized = false
	_context.file = nil
	_context.messagesQueue = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	
	_exitGroup.Done ()
	
	return _error
}


func outputStdoutLooper (_context *OutputStdoutContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	log.Printf ("[345aa7cc]  output stdout started;\n")
	
	_stop : for {
		select {
			
			case _message := <- _context.messagesQueue :
				if _error := outputStdoutProcess (_context, _message); _error != nil {
					logError (_error, "[0c142768]  output stdout failed processing message!  ignoring!")
				}
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						log.Printf ("[bb274e9a]  output stdout interrupted by signal:  `%s`!  terminating!\n", _signal)
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[68802f72]  output stdout interrupted by unexpected signal:  `%s`!  ignoring!\n", _signal)
				}
		}
	}
	
	log.Printf ("[84cc1079]  output stdout finalizing...\n")
	if _error := outputStdoutFinalize (_context); _error != nil {
		logError (_error, "[021ed52c]  output stdout failed to finalize!  ignoring!")
		return _error
	}
	
	log.Printf ("[7d12bc82]  output stdout terminated;\n")
	return nil
}


func outputStdoutProcess (_context *OutputStdoutContext, _message *Message) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[e360d509]  output stdout is not initialized!")
	}
	
	_configuration := _context.configuration
	
	return outputStreamProcess (_context.file, _message, _configuration.JsonPretty, _configuration.JsonSequence, _configuration.Flush)
}




func outputFileInitialize (_configuration *OutputFileConfiguration, _messagesQueue <-chan *Message, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*OutputFileContext, error) {
	
	_context := & OutputFileContext {
			configuration : _configuration,
			initialized : true,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	log.Printf ("[83c65034]  output file starting...\n")
	
	_exitGroup.Add (1)
	
	go outputFileLooper (_context)
	
	return _context, nil
}


func outputFileFinalize (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_error := outputFileClose (_context, true)
	
	_exitGroup := _context.exitGroup
	
	_context.initialized = false
	_context.messagesQueue = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	
	_exitGroup.Done ()
	
	return _error
}


func outputFileLooper (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	log.Printf ("[10354775]  output file started;\n")
	
	_configuration := _context.configuration
	_ticker := time.NewTicker (_configuration.TickerInterval)
	
	_stop : for {
		select {
			
			case _message := <- _context.messagesQueue :
				outputFileTimestamp (_context)
				if _error := outputFileProcess (_context, _message); _error != nil {
					logError (_error, "[5fd6c601]  output file failed processing message!  ignoring!")
				}
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						log.Printf ("[c3f6650e]  output file interrupted by signal:  `%s`!  terminating!\n", _signal)
						break _stop
					
					case syscall.SIGHUP :
						log.Printf ("[8198be0d]  output file interrupted by signal:  `%s`!  flushing...\n", _signal)
						if _error := outputFileClose (_context, false); _error != nil {
							logError (_error, "[7017a4da]  output file failed flushing!  ignoring!")
						}
					
					default :
						log.Printf ("[3b5a9896]  output file interrupted by unexpected signal:  `%s`!  ignoring!\n", _signal)
				}
			
			case <- _ticker.C :
				outputFileTimestamp (_context)
				if _error := outputFileClosePerhaps (_context); _error != nil {
					logError (_error, "[9bc52216]  output file failed flushing!  ignoring!")
				}
		}
	}
	
	log.Printf ("[c0cd4992]  output file finalizing...\n")
	if _error := outputFileFinalize (_context); _error != nil {
		logError (_error, "[86400d3b]  output file failed to finalize!  ignoring!")
		return _error
	}
	
	log.Printf ("[cdecc5a4]  output file terminated;\n")
	return nil
}


func outputFileProcess (_context *OutputFileContext, _message *Message) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[a73865e2]  output file is not initialized!")
	}
	
	_configuration := _context.configuration
	
	if _error := outputFileClosePerhaps (_context); _error != nil {
		logError (_error, "")
	}
	if _error := outputFileOpen (_context); _error != nil {
		logError (_error, "")
	}
	
	_context.currentMessages += 1
	
	if _context.currentFile != nil {
		return outputStreamProcess (_context.currentFile, _message, _configuration.JsonPretty, _configuration.JsonSequence, _configuration.Flush)
	} else {
		return fmt.Errorf ("[eb1083ab]  output file is not opened!")
	}
}


func outputFileTimestamp (_context *OutputFileContext) () {
	
	_timestamp := time.Now ()
	_timestampToken := _timestamp.Format (_context.configuration.CurrentTimestamp)
	
	_context.nowTimestamp = _timestamp
	_context.nowTimestampToken = _timestampToken
}


func outputFileOpen (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[32867341]  output file is not initialized!")
	}
	if _context.currentFile != nil {
		return nil
	}
	
	_configuration := _context.configuration
	
	_context.currentTimestamp = _context.nowTimestamp
	_context.currentTimestampToken = _context.nowTimestampToken
	_context.currentMessages = 0
	
	_context.currentCurrentPath = fmt.Sprintf (
			"%s%c%s%s-%06x-%06x%s",
			_configuration.CurrentStorePath,
			os.PathSeparator,
			_configuration.CurrentPrefix,
			_context.nowTimestampToken,
			os.Getpid () & 0xffffff,
			_context.nowTimestamp.Unix () & 0xffffff,
			_configuration.CurrentSuffix,
		)
	
	_context.currentArchivedPath = fmt.Sprintf (
			"%s%c%s%s-%06x-%06x%s",
			_configuration.ArchivedStorePath,
			os.PathSeparator,
			_configuration.ArchivedPrefix,
			_context.nowTimestamp.Format (_configuration.ArchivedTimestamp),
			os.Getpid () & 0xffffff,
			_context.nowTimestamp.Unix () & 0xffffff,
			_configuration.ArchivedSuffix,
		)
	
	if _error := os.MkdirAll (path.Dir (_context.currentCurrentPath), _configuration.StoreMode); _error != nil {
		log.Printf ("[9e694a9c]  failed opening current output file to `%s` (mkdir)!  ignoring!\n", _context.currentCurrentPath)
		logError (_error, "")
	}
	if _file, _error := os.OpenFile (_context.currentCurrentPath, os.O_CREATE | os.O_EXCL | os.O_WRONLY | os.O_APPEND, _configuration.FileMode); _error == nil {
		log.Printf ("[27432827]  succeeded opening current output file `%s`;\n", _context.currentCurrentPath)
		_context.currentFile = _file
	} else {
		log.Printf ("[27432827]  failed opening current output file `%s` (open)!  ignoring!\n", _context.currentCurrentPath)
		logError (_error, "")
		_context.currentFile = nil
	}
	
	if _configuration.CurrentSymlinkPath != "" {
		if _error := os.Remove (_configuration.CurrentSymlinkPath); (_error != nil) && ! os.IsNotExist (_error) {
			logError (_error, "[fb4f5f7b]  failed symlink-ing current output file (unlink)!  ignoring!")
		}
		if _relativePath, _error := filepath.Rel (path.Dir (_configuration.CurrentSymlinkPath), _context.currentCurrentPath); _error != nil {
			logError (_error, "[a578ba45]  failed symlink-ing current output file (relpath)!  ignoring!")
		} else if _error := os.Symlink (_relativePath, _configuration.CurrentSymlinkPath); _error != nil {
			logError (_error, "[f0ccc0b5]  failed symlink-ing current output file (relpath)!  ignoring!")
		}
	}
	
	return nil
}


func outputFileClosePerhaps (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[96c62f00]  output file is not initialized!")
	}
	if _context.currentFile == nil {
		return nil
	}
	
	_configuration := _context.configuration
	
	_shouldClose := false
	if ! _shouldClose && (_context.currentMessages >= _configuration.Messages) {
		if _configuration.Debug {
			log.Printf ("[6608f486]  current file has reached its maximum messages count limit;\n")
		}
		_shouldClose = true
	}
	if ! _shouldClose && (_context.nowTimestamp.Sub (_context.currentTimestamp) >= _configuration.Timeout) {
		if _configuration.Debug {
			log.Printf ("[963bf22e]  current file has reached its maximum age limit;\n")
		}
		_shouldClose = true
	}
	if ! _shouldClose && (_context.currentTimestampToken != _context.nowTimestampToken) {
		if _configuration.Debug {
			log.Printf ("[214f5ea7]  current file has a different timestamp token;\n")
		}
		_shouldClose = true
	}
	
	if _shouldClose {
		return outputFileClose (_context, false)
	} else {
		return nil
	}
}


func outputFileClose (_context *OutputFileContext, _wait bool) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[7ac83fe5]  output file is not initialized!")
	}
	if _context.currentFile == nil {
		return nil
	}
	
	_configuration := _context.configuration
	
	if _error := _context.currentFile.Close (); _error == nil {
		log.Printf ("[c1b80cc7]  succeeded closing previous output file `%s`;\n", _context.currentCurrentPath)
	} else {
		log.Printf ("[c1b80cc7]  failed closing previous output file `%s`!  ignoring!\n", _context.currentCurrentPath)
		logError (_error, "")
	}
	
	if _error := os.Remove (_configuration.CurrentSymlinkPath); (_error != nil) && ! os.IsNotExist (_error) {
		logError (_error, "[5df85030]  failed symlink-ing current output file (unlink)!  ignoring!")
	}
	
	if _context.currentCurrentPath != _context.currentArchivedPath {
		if _error := os.MkdirAll (path.Dir (_context.currentArchivedPath), _configuration.StoreMode); _error != nil {
			log.Printf ("[0febdcf9]  failed renaming previous output file to `%s` (mkdir)!  ignoring!\n", _context.currentArchivedPath)
			logError (_error, "")
		}
		if _error := os.Rename (_context.currentCurrentPath, _context.currentArchivedPath); _error == nil {
			log.Printf ("[04157e71]  succeeded renaming previous output file to `%s`;\n", _context.currentArchivedPath)
		} else {
			log.Printf ("[7ad610e7]  failed renaming previous output file to `%s` (rename)!  ignoring!\n", _context.currentArchivedPath)
			logError (_error, "")
		}
	}
	
	if _configuration.ArchivedCompressSuffix != "" {
		if _error := outputFileCompress (_context, _wait); _error != nil {
			log.Printf ("[9e80c303]  failed compressing previous output file to `%s` (rename)!  ignoring!\n", _context.currentArchivedPath)
			logError (_error, "")
		}
	}
	
	_context.currentFile = nil
	
	return nil
}


func outputFileCompress (_context *OutputFileContext, _wait bool) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[f02c854b]  output file is not initialized!")
	}
	
	_configuration := _context.configuration
	
	_uncompressedPath := _context.currentArchivedPath
	_compressedPathFinal := _uncompressedPath + _configuration.ArchivedCompressSuffix
	_compressedPathTemp := _uncompressedPath + _configuration.ArchivedCompressSuffix + ".tmp"
	
	log.Printf ("[2d5bbfb2]  compressing previous output file to `%s`...\n", _compressedPathFinal)
	
	var _uncompressedFile *os.File
	var _compressedFile *os.File
	var _process *os.Process
	_exitGroup := _context.exitGroup
	
	_exitGroup.Add (1)
	
	_abort := func () (error) {
		if _uncompressedFile != nil {
			_uncompressedFile.Close ()
		}
		if _compressedFile != nil {
			_compressedFile.Close ()
			os.Remove (_compressedPathTemp)
		}
		if _process != nil {
			_process.Kill ()
			_process.Wait ()
		}
		_exitGroup.Done ()
		return fmt.Errorf ("[c3a4f5db]  failed compressing file!")
	}
	
	if _file, _error := os.OpenFile (_uncompressedPath, os.O_RDONLY, _configuration.FileMode); _error == nil {
		_uncompressedFile = _file
	} else {
		logError (_error, "[6a38d1df]  failed opening uncompressed file!")
		return _abort ()
	}
	
	if _file, _error := os.OpenFile (_compressedPathTemp, os.O_CREATE | os.O_EXCL | os.O_WRONLY | os.O_APPEND, _configuration.FileMode); _error == nil {
		_compressedFile = _file
	} else {
		logError (_error, "[36b2959a]  failed opening compressed file!")
		return _abort ()
	}
	
	_command := exec.Command (_configuration.ArchivedCompressCommand[0], _configuration.ArchivedCompressCommand[1:] ...)
	_command.Stdin = _uncompressedFile
	_command.Stdout = _compressedFile
	if _error := _command.Start (); _error == nil {
		_process = _command.Process
	} else {
		logError (_error, "[d591be92]  failed executing compress process (exec)!")
		return _abort ()
	}
	
	_uncompressedFile.Close ()
	_uncompressedFile = nil
	_compressedFile.Close ()
	_compressedFile = nil
	
	_finalize := func () (error) {
		if _state, _error := _process.Wait (); _error == nil {
			if ! _state.Success () {
				log.Printf ("[09463fb9]  failed executing compress process (exit):  `%s`!\n", _state.Sys ())
				_process = nil
				return _abort ()
			}
		} else {
			logError (_error, "[30dd81af]  failed executing compress process (wait)!")
			_process = nil
			return _abort ()
		}
		if _error := os.Rename (_compressedPathTemp, _compressedPathFinal); _error != nil {
			logError (_error, "[dd8ff061]  failed renaming compressed file!")
			return _abort ()
		}
		if _error := os.Remove (_uncompressedPath); _error != nil {
			logError (_error, "[9391f70d]  failed deleting uncompressed file!")
			return _abort ()
		}
		log.Printf ("[9b4015d2]  succeeded compressing previous output file to `%s`;\n", _compressedPathFinal)
		_exitGroup.Done ()
		return nil
	}
	
	if _wait {
		return _finalize ()
	} else {
		go _finalize ()
		return nil
	}
}




func outputStreamProcess (_stream *os.File, _message *Message, _pretty bool, _sequence bool, _flush bool) (error) {
	
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
		return fmt.Errorf ("[82772647]  buffer written partially:  `%d` of `%d`!", _size, len (_buffer))
	}
	
	if _flush {
		if _error := _stream.Sync (); _error != nil {
			return _error
		}
	}
	
	return nil
}




func main_0 () (error) {
	
	
	log.Printf ("[69922ece]  configuring services...\n")
	var _configuration *Configuration = nil
	if _configuration_0, _error := configure (os.Args[1:]); _error == nil {
		_configuration = _configuration_0
	} else {
		return _error
	}
	
	
	log.Printf ("[e1603153]  initializing services...\n")
	var _syslogQueueSize uint = DefaultInputSyslogQueueSize
	if _configuration.InputSyslog != nil {
		_syslogQueueSize = _configuration.InputSyslog.QueueSize
	}
	_syslogQueue := make (chan syslog_format.LogParts, _syslogQueueSize)
	
	_messagesQueues := make ([] chan<- *Message, 0)
	_mainSignalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
	_serviceSignalsQueues := make ([] chan os.Signal, 0)
	_exitGroup := & sync.WaitGroup {}
	
	
	// signal.Ignore ()
	signal.Notify (_mainSignalsQueue, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify (_mainSignalsQueue, syscall.SIGHUP)
	signal.Notify (_mainSignalsQueue, syscall.SIGUSR1, syscall.SIGUSR2)
	
	
	var _inputSyslogContext *InputSyslogContext = nil
	if _configuration.InputSyslog != nil {
		log.Printf ("[1b82323e]  initializing input syslog...\n")
		_configuration := _configuration.InputSyslog
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputSyslogInitialize (_configuration, _syslogQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputSyslogContext = _context
			defer inputSyslogFinalize (_inputSyslogContext)
		} else {
			return _error
		}
	}
	
	
	var _outputStdoutContext *OutputStdoutContext = nil
	if _configuration.OutputStdout != nil {
		log.Printf ("[cf9ea565]  initializing output stdout...\n")
		_configuration := _configuration.OutputStdout
		_messagesQueue := make (chan *Message, _configuration.QueueSize)
		_messagesQueues = append (_messagesQueues, _messagesQueue)
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := outputStdoutInitialize (_configuration, _messagesQueue, _signalsQueue, _exitGroup); _error == nil {
			_outputStdoutContext = _context
			defer outputStdoutFinalize (_outputStdoutContext)
		} else {
			return _error
		}
	}
	
	
	var _outputFileContext *OutputFileContext = nil
	if _configuration.OutputFile != nil {
		log.Printf ("[41085a24]  initializing output file...\n")
		_configuration := _configuration.OutputFile
		_messagesQueue := make (chan *Message, _configuration.QueueSize)
		_messagesQueues = append (_messagesQueues, _messagesQueue)
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := outputFileInitialize (_configuration, _messagesQueue, _signalsQueue, _exitGroup); _error == nil {
			_outputFileContext = _context
			defer outputFileFinalize (_outputFileContext)
		} else {
			return _error
		}
	}
	
	
	var _parserContext *ParserContext = nil
	{
		log.Printf ("[63ca1586]  initializing parser...\n")
		_configuration := _configuration.Parser
		if _context, _error := parserInitialize (_configuration); _error == nil {
			_parserContext = _context
			defer parserFinalize (_parserContext)
		} else {
			return _error
		}
	}
	
	var _dequeueContext *DequeueContext = nil
	{
		log.Printf ("[b86862c9]  initializing dequeue...\n")
		_configuration := _configuration.Dequeue
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := dequeueInitialize (_configuration, _parserContext, _syslogQueue, _messagesQueues, _signalsQueue, _exitGroup); _error == nil {
			_dequeueContext = _context
			defer dequeueFinalize (_dequeueContext)
		} else {
			return _error
		}
	}
	
	
	log.Printf ("[e5759817]  initialized services!\n")
	
	
	_stop : for {
		select {
			case _signal := <- _mainSignalsQueue :
				for _, _signalsQueue := range _serviceSignalsQueues {
					select {
						case _signalsQueue <- _signal :
						default :
					}
				}
				switch _signal {
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						break _stop
				}
		}
	}
	
	
	go func () () {
		for {
			time.Sleep (1 * time.Second)
			log.Printf ("[cd90630d]  terminating services...\n")
			for _, _signalsQueue := range _serviceSignalsQueues {
				select {
					case _signalsQueue <- syscall.SIGTERM :
					default :
				}
			}
		}
	} ()
	
	
	_exitGroup.Wait ()
	
	log.Printf ("[b3181816]  terminated services!\n")
	
	
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

