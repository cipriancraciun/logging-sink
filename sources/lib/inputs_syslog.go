

package lib


import "bufio"
import "crypto/sha256"
import "encoding/json"
import "encoding/hex"
import "fmt"
import "log"
import "os"
import "strings"
import "sync"
import "syscall"
import "time"

import syslog "gopkg.in/mcuadros/go-syslog.v2"
import syslog_format "gopkg.in/mcuadros/go-syslog.v2/format"




type InputSyslogConfiguration struct {
	
	Identifier string
	ListenTcp string
	ListenUdp string
	ListenUnix string
	Timeout time.Duration
	FormatName string
	FormatParser syslog_format.Format
	ParseJson bool
	Debug bool
}


type InputSyslogContext struct {
	
	configuration *InputSyslogConfiguration
	initialized bool
	
	server *syslog.Server
	
	messagesQueue chan<- *CollectorMessage
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




func inputSyslogInitialize (_configuration *InputSyslogConfiguration, _messagesQueue chan<- *CollectorMessage, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*InputSyslogContext, error) {
	
	_server := syslog.NewServer ()
	
	if _configuration.Debug {
		log.Printf ("[ii] [fe61c4fc]  input syslog using protocol `%s`;\n", _configuration.FormatName)
	}
	_serverFormat := & InputSyslogFormat {
			delegate : _configuration.FormatParser,
		}
	_server.SetFormat (_serverFormat)
	
	if _configuration.Debug {
		log.Printf ("[ii] [f989cab8]  input syslog using timeout of `%s`...\n", _configuration.Timeout)
	}
	_server.SetTimeout (_configuration.Timeout.Nanoseconds () / 1000000)
	
	_listening := false
	if _configuration.ListenTcp != "" {
		if _configuration.Debug {
			log.Printf ("[ii] [42aa16d0]  input syslog listening on TCP at `%s`...\n", _configuration.ListenTcp)
		}
		if _error := _server.ListenTCP (_configuration.ListenTcp); _error != nil {
			_server.Kill ()
			return nil, _error
		}
		_listening = true
	}
	if _configuration.ListenUdp != "" {
		if _configuration.Debug {
			log.Printf ("[ii] [bb824266]  input syslog listening on UDP at `%s`...\n", _configuration.ListenUdp)
		}
		if _error := _server.ListenUDP (_configuration.ListenUdp); _error != nil {
			_server.Kill ()
			return nil, _error
		}
		_listening = true
	}
	if _configuration.ListenUnix != "" {
		if _configuration.Debug {
			log.Printf ("[ii] [eba876e1]  input syslog listening on Unix at `%s`...\n", _configuration.ListenUnix)
		}
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
	
	if _configuration.Debug {
		log.Printf ("[ii] [f143c879]  input syslog starting...\n")
	}
	
	_context := & InputSyslogContext {
			configuration : _configuration,
			initialized : true,
			server : _server,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	_server.SetHandler ((*InputSyslogHandler) (_context))
	
	if _error := _server.Boot (); _error != nil {
		return nil, _error
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
	_context.messagesQueue = nil
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
	
	_configuration := _context.configuration
	
	if _configuration.Debug {
		log.Printf ("[ii] [58bc4187]  input syslog started;\n")
	}
	
	_stop : for {
		select {
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [56ebeed8]  input syslog interrupted by signal:  `%s`;  terminating!\n", _signal)
						}
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[ee] [b0635598]  input syslog interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [22397366]  input syslog finalizing...\n")
	}
	if _error := inputSyslogFinalize (_context); _error != nil {
		logError (_error, "[0d40d40b]  input syslog failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [50f377f5]  input syslog terminated;\n")
	return nil
}




type InputSyslogFormat struct {
	delegate syslog_format.Format
}

func (format *InputSyslogFormat) GetParser (_message []byte) (syslog_format.LogParser) {
	_sha256Raw := sha256.Sum256 (_message)
	_sha256Hex := hex.EncodeToString (_sha256Raw[:])
	return & InputSyslogParser {
			delegate : format.delegate.GetParser (_message),
			messageRaw : _message,
			messageSha256 : _sha256Hex,
		}
}

func (format *InputSyslogFormat) GetSplitFunc () (bufio.SplitFunc) {
	return format.delegate.GetSplitFunc ()
}




type InputSyslogParser struct {
	delegate syslog_format.LogParser
	messageRaw []byte
	messageSha256 string
}

func (parser *InputSyslogParser) Parse () (error) {
	return parser.delegate.Parse ()
}

func (parser *InputSyslogParser) Location (_location *time.Location) () {
	parser.delegate.Location (_location)
}

func (parser *InputSyslogParser) Dump () (syslog_format.LogParts) {
	_message := parser.delegate.Dump ()
	if parser.messageRaw != nil {
		_message["_message_raw"] = parser.messageRaw
	}
	if parser.messageSha256 != "" {
		_message["_message_sha256"] = parser.messageSha256
	}
	return _message
}




type InputSyslogHandler InputSyslogContext

func (_context_0 *InputSyslogHandler) Handle (_message syslog_format.LogParts, _ int64, _error error) () {
	_context := (*InputSyslogContext) (_context_0)
	if _error == nil {
		if _error := inputSyslogProcess (_context, _message); _error != nil {
			logError (_error, "[eca965a0]  input syslog failed to process message;  ignoring!")
		}
	} else {
		logError (_error, "[258484e5]  input syslog failed to parse message;  ignoring!")
	}
}


func inputSyslogProcess (_context *InputSyslogContext, _syslogMessage syslog_format.LogParts) (error) {
	
	_configuration := _context.configuration
	
	for _key, _value := range _syslogMessage {
		_shouldDelete := false
		switch _value {
			case "", "-" :
				_shouldDelete = true
			case nil :
				_shouldDelete = true
		}
		if _shouldDelete {
			delete (_syslogMessage, _key)
		}
	}
	
	var _messageText string
	if _value, _error := syslogPartExtractAsString (_syslogMessage, []string {"message", "content"}, true, false); _error == nil {
		_messageText = _value
	} else {
		return _error
	}
	
	var _messageJson json.RawMessage = nil
	if _configuration.ParseJson {
		_messageText_0 := strings.TrimSpace (_messageText)
		if strings.HasPrefix (_messageText_0, "{") && strings.HasSuffix (_messageText_0, "}") {
			if _error := json.Unmarshal ([]byte (_messageText_0), &_messageJson); _error == nil {
				// NOP
			}
		}
	}
	
	var _timestamp time.Time
	if _value, _error := syslogPartExtractAsTime (_syslogMessage, []string {"timestamp"}, true, false); _error == nil {
		_timestamp = _value
	} else {
		return _error
	}
	
	var _node string
	if _value, _error := syslogPartExtractAsString (_syslogMessage, []string {"hostname"}, true, false); _error == nil {
		_node = _value
	} else {
		return _error
	}
	
	var _service string
	if _value, _error := syslogPartExtractAsString (_syslogMessage, []string {"app_name", "tag"}, true, false); _error == nil {
		_service = _value
	} else {
		return _error
	}
	
	var _type string
	if _value, _error := syslogPartExtractAsString (_syslogMessage, []string {"msg_id"}, true, true); _error == nil {
		_type = _value
	} else {
		return _error
	}
	
	var _severity int
	if _value, _error := syslogPartExtractAsInt (_syslogMessage, []string {"severity"}, false, false); _error == nil {
		_severity = _value
	}
	var _levelUnix int8
	var _levelText string
	switch _severity {
		case 0 :
			_levelUnix = 1
			_levelText = "emergency"
		case 1 :
			_levelUnix = 2
			_levelText = "alert"
		case 2 :
			_levelUnix = 3
			_levelText = "critical"
		case 3 :
			_levelUnix = 4
			_levelText = "error"
		case 4 :
			_levelUnix = 5
			_levelText = "warning"
		case 5 :
			_levelUnix = 6
			_levelText = "notice"
		case 6 :
			_levelUnix = 7
			_levelText = "informative"
		case 7 :
			_levelUnix = 8
			_levelText = "debug"
		default :
			log.Printf ("[ee] [a11d7539]  syslog message has an invalid severity `%d`;  ignoring!\n", _severity)
			_levelUnix = -1
			_levelText = "<undefined>"
	}
	
	var _messageRaw []byte
	if _value, _error := syslogPartExtractAsBytes (_syslogMessage, []string {"_message_raw"}, true, false); _error == nil {
		_messageRaw = _value
	} else {
		return _error
	}
	
	var _messageSha256 string
	if _value, _error := syslogPartExtractAsString (_syslogMessage, []string {"_message_sha256"}, true, false); _error == nil {
		_messageSha256 = _value
	} else {
		return _error
	}
	
	_collectorMessage := & CollectorMessage {
			CollectorType : SyslogCollectorType,
			CollectorIdentifier : _configuration.Identifier,
			MessageRaw : _messageRaw,
			MessageSha256 : _messageSha256,
			MessageText : _messageText,
			MessageJson : _messageJson,
			MessageMetaData : & SyslogMessageMetaData {
					Schema : SyslogMessageMetaDataSchema,
					Protocol : _configuration.FormatName,
					Timestamp : _timestamp,
					TimestampUnix : uint64 (_timestamp.UnixNano () / 1000000),
					Node : _node,
					Service : _service,
					Type : _type,
					Level : _levelText,
					LevelUnix : _levelUnix,
					Fields : _syslogMessage,
				},
		}
	
	_context.messagesQueue <- _collectorMessage
	
	return nil
}




func syslogPartExtract (_message syslog_format.LogParts, _keys []string, _delete bool, _ignore bool) (interface{}, error) {
	for _, _key := range _keys {
		if _value, _exists := _message[_key]; _exists {
			if _delete {
				delete (_message, _key)
			}
			return _value, nil
		}
	}
	if _ignore {
		return nil, nil
	} else {
		return nil, fmt.Errorf ("[3177e6e2]  syslog message is missing part with key `%q`", _keys)
	}
}

func syslogPartExtractAsString (_message syslog_format.LogParts, _keys []string, _delete bool, _ignore bool) (string, error) {
	if _value, _error := syslogPartExtract (_message, _keys, _delete, _ignore); _error == nil {
		if _value != nil {
			if _value, _isValid := _value.(string); _isValid {
				return _value, nil
			} else {
				return "", fmt.Errorf ("[00e3014d]  syslog message has invalid part with key `%q`:  `%#v`", _keys, _value)
			}
		} else {
			return "", nil
		}
	} else {
		return "", _error
	}
}

func syslogPartExtractAsBytes (_message syslog_format.LogParts, _keys []string, _delete bool, _ignore bool) ([]byte, error) {
	if _value, _error := syslogPartExtract (_message, _keys, _delete, _ignore); _error == nil {
		if _value != nil {
			if _value, _isValid := _value.([]byte); _isValid {
				return _value, nil
			} else {
				return nil, fmt.Errorf ("[9f0ac23f]  syslog message has invalid part with key `%q`:  `%#v`", _keys, _value)
			}
		} else {
			return nil, nil
		}
	} else {
		return nil, _error
	}
}

func syslogPartExtractAsInt (_message syslog_format.LogParts, _keys []string, _delete bool, _ignore bool) (int, error) {
	if _value, _error := syslogPartExtract (_message, _keys, _delete, _ignore); _error == nil {
		if _value != nil {
			if _value, _isValid := _value.(int); _isValid {
				return _value, nil
			} else {
				return 0, fmt.Errorf ("[3507b378]  syslog message has invalid part with key `%q`:  `%#v`", _keys, _value)
			}
		} else {
			return 0, nil
		}
	} else {
		return 0, _error
	}
}

func syslogPartExtractAsTime (_message syslog_format.LogParts, _keys []string, _delete bool, _ignore bool) (time.Time, error) {
	if _value, _error := syslogPartExtract (_message, _keys, _delete, _ignore); _error == nil {
		if _value != nil {
			if _value, _isValid := _value.(time.Time); _isValid {
				return _value, nil
			} else {
				return time.Time {}, fmt.Errorf ("[a9d64fc8]  syslog message has invalid part with key `%q`:  `%#v`", _keys, _value)
			}
		} else {
			return time.Time {}, nil
		}
	} else {
		return time.Time {}, _error
	}
}


