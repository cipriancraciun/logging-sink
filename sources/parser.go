

package main


import "encoding/json"
import "fmt"
import "io"
import "log"
import "os"
import "os/exec"
import "time"




type ParserConfiguration struct {
	
	MessageJson bool
	MessageRaw bool
	MessageSha256 bool
	Debug bool
	
	ExternalCommand []string
	ExternalReplace bool
}


type ParserContext struct {
	
	configuration *ParserConfiguration
	initialized bool
	
	externalCommand *exec.Cmd
	externalOutputRaw io.WriteCloser
	externalInputRaw io.ReadCloser
	externalOutputJson *json.Encoder
	externalInputJson *json.Decoder
}




func parserInitialize (_configuration *ParserConfiguration) (*ParserContext, error) {
	
	_context := & ParserContext {
			configuration : _configuration,
			initialized : true,
		}
	
	if _configuration.ExternalCommand != nil {
		if _error := parserExternalCommandStart (_context); _error != nil {
			return nil, _error
		}
	}
	
	return _context, nil
}




func parserFinalize (_context *ParserContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_configuration := _context.configuration
	
	var _error error = nil
	if _configuration.ExternalCommand != nil {
		_error = parserExternalCommandStop (_context)
	}
	
	_context.initialized = false
	
	return _error
}




func parserProcess (_context *ParserContext, _collectorMessage *CollectorMessage, _sequence uint64) (*Message, error) {
	
	if ! _context.initialized {
		return nil, fmt.Errorf ("[6572b28d]  parser is not initialized!")
	}
	
	_configuration := _context.configuration
	
	_timestamp := time.Now ()
	
	_collectorType := _collectorMessage.CollectorType
	_collectorIdentifier := _collectorMessage.CollectorIdentifier
	_messageRaw := _collectorMessage.MessageRaw
	_messageSha256 := _collectorMessage.MessageSha256
	_messageText := _collectorMessage.MessageText
	_messageJson := _collectorMessage.MessageJson
	_messageMetaData := _collectorMessage.MessageMetaData
	
	_message := & Message {
			Schema : MessageSchema,
			SubSchema : "",
			Sequence : _sequence,
			Timestamp : _timestamp,
			TimestampUnix : uint64 (_timestamp.UnixNano () / 1000000),
			CollectorType : _collectorType,
			CollectorIdentifier : _collectorIdentifier,
			MessageRaw : _messageRaw,
			MessageSha256 : _messageSha256,
			MessageText : _messageText,
			MessageJson : _messageJson,
			MessageMetaData : _messageMetaData,
		}
	
	if _configuration.ExternalCommand != nil {
		if _messageReplacement, _error := parserExternalCommandProcess (_context, _message); _error == nil {
			_message = _messageReplacement
		} else {
			logError (_error, "[ee] [5359422a]  parser external command failed to process message;  ignoring!")
		}
	}
	
	if _message != nil {
		if _message.MessageJson != nil {
			_message.MessageText = ""
		}
		if ! _configuration.MessageRaw && ((_message.MessageText != "") || (_message.MessageJson != nil)) {
			_message.MessageRaw = nil
		}
		if ! _configuration.MessageSha256 {
			_message.MessageSha256 = ""
		}
	}
	
	return _message, nil
}




func parserExternalCommandStart (_context *ParserContext) (error) {
	
	_configuration := _context.configuration
	
	if _context.externalCommand != nil {
		return nil
	}
	
	if _configuration.ExternalCommand == nil {
		return nil
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [899b93ef]  parser external process starting: `%q`...\n", _configuration.ExternalCommand)
	}
	
	_command := exec.Command (_configuration.ExternalCommand[0], _configuration.ExternalCommand[1:] ...)
	_command.Stderr = os.Stderr
	
	var _commandStdin io.WriteCloser
	if _stream, _error := _command.StdinPipe (); _error == nil {
		_commandStdin = _stream
	} else {
		logError (_error, "")
		return fmt.Errorf ("[64960c3e]  parser external process failed to initialize (stdin)!")
	}
	
	var _commandStdout io.ReadCloser
	if _stream, _error := _command.StdoutPipe (); _error == nil {
		_commandStdout = _stream
	} else {
		logError (_error, "")
		return fmt.Errorf ("[8609de71]  parser external process failed to initialize (stdout)!")
	}
	
	if _error := _command.Start (); _error != nil {
		logError (_error, "")
		return fmt.Errorf ("[6b9e2bd0]  parser external process failed to initialize (exec)!")
	}
	
	_context.externalCommand = _command
	_context.externalOutputRaw = _commandStdin
	_context.externalInputRaw = _commandStdout
	
	_context.externalOutputJson = json.NewEncoder (_context.externalOutputRaw)
	_context.externalInputJson = json.NewDecoder (_context.externalInputRaw)
	
	if _configuration.ExternalReplace {
		_context.externalInputJson.DisallowUnknownFields ()
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [5a58d261]  parser external process started;\n")
	}
	
	return nil
}




func parserExternalCommandStop (_context *ParserContext) (error) {
	
	_configuration := _context.configuration
	
	if _context.externalOutputRaw != nil {
		_context.externalOutputRaw.Close ()
		_context.externalOutputRaw = nil
		_context.externalOutputJson = nil
	}
	if _context.externalInputRaw != nil {
		_context.externalInputRaw.Close ()
		_context.externalInputRaw = nil
		_context.externalInputJson = nil
	}
	
	if _context.externalCommand != nil {
		
		if _configuration.Debug {
			log.Printf ("[ii] [6b0a0f45]  parser external process terminating...\n")
		}
		
		time.Sleep (500 * time.Millisecond)
		_context.externalCommand.Process.Kill ()
		_context.externalCommand.Process.Wait ()
		
		if _configuration.Debug {
			log.Printf ("[ii] [3a781f0f]  parser external process terminated;\n")
		}
		
		_context.externalCommand = nil
	}
	
	return nil
}




func parserExternalCommandRestart (_context *ParserContext) (error) {
	if _error := parserExternalCommandStop (_context); _error != nil {
		logError (_error, "[f313cb7f]  parser external failed to stop;  ignoring!")
	}
	if _error := parserExternalCommandStart (_context); _error != nil {
		logError (_error, "[39592e95]  parser external failed to start;  ignoring!")
	}
	return nil
}




func parserExternalCommandProcess (_context *ParserContext, _message *Message) (*Message, error) {
	
	_configuration := _context.configuration
	
	_shouldRestart := false
	_shouldFail := false
	
	if _error := parserExternalCommandStart (_context); _error != nil {
		logError (_error, "[4f52cde3]  parser external failed to start;  ignoring!")
		_shouldFail = true
	}
	
	if _context.externalOutputJson != nil {
		if _error := _context.externalOutputJson.Encode (_message); _error != nil {
			logError (_error, "[341a1275]  parser external failed to encode and output message;  ignoring!")
			_shouldRestart = true
			_shouldFail = true
		} else {
			if _context.externalInputJson != nil {
				if _configuration.ExternalReplace {
					var _messageReplacement *Message
					if _error := _context.externalInputJson.Decode (&_messageReplacement); _error != nil {
						logError (_error, "[f533846e]  parser external failed to input and decode message replacement;  ignoring!")
						_shouldRestart = true
						_shouldFail = true
					} else {
						_message = _messageReplacement
					}
				} else {
					var _messageExtra json.RawMessage = nil
					if _error := _context.externalInputJson.Decode (&_messageExtra); _error != nil {
						logError (_error, "[14b47643]  parser external failed to input and decode message extra;  ignoring!")
						_shouldRestart = true
						_shouldFail = true
					} else {
						_message.MessageExtra = _messageExtra
					}
				}
			}
		}
	}
	
	if _shouldRestart {
		log.Printf ("[ii]  parser external restarting...\n")
		if _error := parserExternalCommandRestart (_context); _error != nil {
			logError (_error, "[0a328daf]  parser external failed to restart;  ignoring!")
		}
	}
	
	if _shouldFail {
		return nil, fmt.Errorf ("[f8919556]  parser external failed!")
	} else {
		return _message, nil
	}
}


