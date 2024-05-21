

package lib


import "context"
import "encoding/json"
import "fmt"
import "log"
import "os"
import "strings"
import "sync"
import "syscall"
import "time"

import mqtt "github.com/pascaldekloe/mqtt"




type OutputMqttFlags struct {
	
	Enabled *FlagsBool `long:"output-mqtt-enabled" value-name:"{bool}"`
	ConnectTcp *string `long:"output-mqtt-connect-tcp" value-name:"{ip}:{port}"`
	Topic *string `long:"output-mqtt-topic" value-name:"{topic}"`
	TopicSuffix *string `long:"output-mqtt-topic-suffix" value-name:"{pattern} (see manual)"`
	Client *string `long:"output-mqtt-client" value-name:"{identifier}"`
	Username *string `long:"output-mqtt-username" value-name:"..." default-mask:"..."`
	Password *string `long:"output-mqtt-password" value-name:"..." default-mask:"..."`
	CleanSession *FlagsBool `long:"output-mqtt-clean-session" value-name:"{bool}"`
	KeepAlive *time.Duration `long:"output-mqtt-keep-alive" value-name:"{duration}"`
	Ping *time.Duration `long:"output-mqtt-ping" value-name:"{duration}"`
	Retry *time.Duration `long:"output-mqtt-retry" value-name:"{duration}"`
	QueueSize *uint `long:"output-mqtt-queue-size" value-name:"{count}"`
	Debug *FlagsBool `long:"output-mqtt-debug" value-name:"{bool}"`
}


type OutputMqttConfiguration struct {
	
	ConnectTcp string
	Topic string
	TopicSuffix string
	Client string
	Username string
	Password string
	CleanSession bool
	KeepAlive time.Duration
	Ping time.Duration
	Retry time.Duration
	QueueSize uint
	Debug bool
}


type OutputMqttContext struct {
	
	configuration *OutputMqttConfiguration
	initialized bool
	
	client *mqtt.Client
	
	messagesQueue <-chan *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




func outputMqttInitialize (_configuration *OutputMqttConfiguration, _messagesQueue <-chan *Message, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*OutputMqttContext, error) {
	
	_clientConfig := & mqtt.Config {}
	
	_connecting := false
	if _configuration.ConnectTcp != "" {
		if _configuration.Debug {
			log.Printf ("[ii] [0eebc502]  output mqtt connecting on TCP at `%s`...\n", _configuration.ConnectTcp)
		}
		_clientConfig.Dialer = mqtt.NewDialer ("tcp", _configuration.ConnectTcp)
		_connecting = true
	}
	
	if !_connecting {
		return nil, fmt.Errorf ("[a06f8953]  output mqtt has no connections configured!")
	}
	
	_clientId := _configuration.Client
	_clientConfig.UserName = _configuration.Username
	_clientConfig.Password = []byte (_configuration.Password)
	_clientConfig.KeepAlive = uint16 (_configuration.KeepAlive.Round (time.Second) .Seconds ())
	_clientConfig.CleanSession = _configuration.CleanSession
	_clientConfig.AtLeastOnceMax = 16384
	_clientConfig.ExactlyOnceMax = 16384
	_clientConfig.PauseTimeout = 6 * time.Second
	
	if _configuration.Debug {
		log.Printf ("[ii] [3f68a560]  output mqtt starting...\n")
	}
	
	var _client *mqtt.Client
	if _client_0, _error := mqtt.VolatileSession (_clientId, _clientConfig); _error == nil {
		_client = _client_0
	} else {
		logError (_error, "[1da01d4b]  output mqtt failed to connect;  aborting!")
		return nil, _error
	}
	
	_context := & OutputMqttContext {
			configuration : _configuration,
			initialized : true,
			client : _client,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	_exitGroup.Add (1)
	
	go outputMqttLooper (_context)
	
	return _context, nil
}




func outputMqttFinalize (_context *OutputMqttContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	var _error error = nil
	if _context.client != nil {
		if _context.configuration.Debug {
			log.Printf ("[ii] [61800990]  output mqtt disconnecting...\n")
		}
		_cancelation := context.Background ()
		_error = _context.client.Disconnect (_cancelation.Done ())
	}
	
	_exitGroup := _context.exitGroup
	
	_context.client = nil
	_context.messagesQueue = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	_context.initialized = false
	
	_exitGroup.Done ()
	
	return _error
}




func outputMqttLooper (_context *OutputMqttContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_configuration := _context.configuration
	_client := _context.client
	
	if _configuration.Debug {
		log.Printf ("[ii] [8f2b4c20]  output mqtt started;\n")
	}
	
	go func () () {
		for {
			if _configuration.Debug {
				log.Printf ("[ii] [a6202e10]  output mqtt receiving message...\n")
			}
			_, _, _error := _client.ReadSlices ()
			if _error == nil {
				log.Printf ("[ww] [c4b2bebd]  output mqtt received message;  ignoring!\n")
			} else if _error == mqtt.ErrClosed {
				return
			} else {
				logError (_error, "[3b3287f9]  output mqtt failed to receive message;  retrying!")
				time.Sleep (_configuration.Retry)
			}
		}
	} ()
	
	go func () () {
		for {
			time.Sleep (_configuration.Ping)
			_cancelation := context.Background ()
			if _configuration.Debug {
				log.Printf ("[ii] [8c494f6c]  output mqtt pinging...\n")
			}
			if _error := _client.Ping (_cancelation.Done ()); _error == nil {
				if _configuration.Debug {
					log.Printf ("[ii] [8b38a6d6]  output mqtt pinged;\n")
				}
				continue
			} else if _error == mqtt.ErrClosed {
				return
			} else {
				logError (_error, "[2e6cd031]  output mqtt failed to ping;  retrying!")
				continue
			}
		}
	} ()
	
	_stop : for {
		select {
			
			case _message := <- _context.messagesQueue :
				if _error := outputMqttProcess (_context, _message); _error != nil {
					logError (_error, "[8f18a0d1]  output stdout failed processing message;  ignoring!")
				}
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [a0947d55]  output mqtt interrupted by signal:  `%s`;  terminating!\n", _signal)
						}
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[ee] [996ebe5a]  output mqtt interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [0aa94ab1]  output mqtt finalizing...\n")
	}
	if _error := outputMqttFinalize (_context); _error != nil {
		logError (_error, "[e7c718df]  output mqtt failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [60bfa05a]  output mqtt terminated;\n")
	return nil
}




func outputMqttProcess (_context *OutputMqttContext, _message *Message) (error) {
	
	_configuration := _context.configuration
	_client := _context.client
	
	var _buffer []byte
	
	if _data, _error := json.Marshal (_message); _error == nil {
		_buffer = _data
	} else {
		return _error
	}
	
	_topic := _configuration.Topic
	_topicSuffix := _configuration.TopicSuffix
	if _topicSuffix != "" {
		//  TODO:  Document these!
		_replacements := make ([]string, 0, 16)
		_replacements = append (_replacements, "@{schema}", _message.Schema)
		_replacements = append (_replacements, "@{collector_type}", _message.CollectorType)
		_replacements = append (_replacements, "@{collector_identifier}", _message.CollectorIdentifier)
		_collectorSchema := ""
		_collectorDefault := ""
		if strings.Contains (_topicSuffix, "@{syslog_") {
			if _metadata, _ok := _message.MessageMetaData.(*SyslogMessageMetaData); _ok {
				_collectorSchema = _metadata.Schema
				_collectorDefault = fmt.Sprintf ("%s/%s/%s/%s", _metadata.Protocol, _metadata.Node, _metadata.Service, _metadata.Level)
				_replacements = append (_replacements, "@{syslog_default}", _collectorDefault)
				_replacements = append (_replacements, "@{syslog_schema}", _metadata.Schema)
				_replacements = append (_replacements, "@{syslog_protocol}", _metadata.Protocol)
				_replacements = append (_replacements, "@{syslog_node}", _metadata.Node)
				_replacements = append (_replacements, "@{syslog_service}", _metadata.Service)
				_replacements = append (_replacements, "@{syslog_type}", _metadata.Type)
				_replacements = append (_replacements, "@{syslog_level}", _metadata.Level)
				_replacements = append (_replacements, "@{syslog_level_unix}", fmt.Sprintf ("%d", _metadata.LevelUnix))
			} else {
				_replacements = append (_replacements, "@{syslog_default}", "")
				_replacements = append (_replacements, "@{syslog_schema}", "")
				_replacements = append (_replacements, "@{syslog_protocol}", "")
				_replacements = append (_replacements, "@{syslog_node}", "")
				_replacements = append (_replacements, "@{syslog_service}", "")
				_replacements = append (_replacements, "@{syslog_type}", "")
				_replacements = append (_replacements, "@{syslog_level}", "")
				_replacements = append (_replacements, "@{syslog_level_unix}", "")
			}
		}
		if strings.Contains (_topicSuffix, "@{http_") {
			if _metadata, _ok := _message.MessageMetaData.(*HttpMessageMetaData); _ok {
				_collectorSchema = _metadata.Schema
				_collectorDefault = fmt.Sprintf ("%s/%s", _metadata.Host, _metadata.Method)
				_replacements = append (_replacements, "@{http_default}", _collectorDefault)
				_replacements = append (_replacements, "@{http_schema}", _metadata.Schema)
				_replacements = append (_replacements, "@{http_protocol}", _metadata.Protocol)
				_replacements = append (_replacements, "@{http_host}", _metadata.Host)
				_replacements = append (_replacements, "@{http_method}", _metadata.Method)
				_replacements = append (_replacements, "@{http_path}", _metadata.Path)
				_replacements = append (_replacements, "@{http_remote_ip}", _metadata.RemoteIp)
			} else {
				_replacements = append (_replacements, "@{http_default}", "")
				_replacements = append (_replacements, "@{http_schema}", "")
				_replacements = append (_replacements, "@{http_protocol}", "")
				_replacements = append (_replacements, "@{http_host}", "")
				_replacements = append (_replacements, "@{http_method}", "")
				_replacements = append (_replacements, "@{http_path}", "")
				_replacements = append (_replacements, "@{http_remote_ip}", "")
			}
		}
		if strings.Contains (_topicSuffix, "@{mqtt_") {
			if _metadata, _ok := _message.MessageMetaData.(*MqttMessageMetaData); _ok {
				_collectorSchema = _metadata.Schema
				_collectorDefault = _metadata.Topic
				_replacements = append (_replacements, "@{mqtt_default}", _collectorDefault)
				_replacements = append (_replacements, "@{mqtt_schema}", _metadata.Schema)
				_replacements = append (_replacements, "@{mqtt_topic}", _metadata.Topic)
			} else {
				_replacements = append (_replacements, "@{mqtt_default}", "")
				_replacements = append (_replacements, "@{mqtt_schema}", "")
				_replacements = append (_replacements, "@{mqtt_topic}", "")
			}
		}
		if strings.Contains (_topicSuffix, "@{collector_schema}") {
			if _collectorSchema == "" {
				if _metadata, _ok := _message.MessageMetaData.(*SyslogMessageMetaData); _ok {
					_collectorSchema = _metadata.Schema
				} else if _metadata, _ok := _message.MessageMetaData.(*HttpMessageMetaData); _ok {
					_collectorSchema = _metadata.Schema
				} else if _metadata, _ok := _message.MessageMetaData.(*MqttMessageMetaData); _ok {
					_collectorSchema = _metadata.Schema
				}
			}
			_collectorSchema = _collectorSchema[len (_message.CollectorType) + 1 :]
			_replacements = append (_replacements, "@{collector_schema}", _collectorSchema)
		}
		if strings.Contains (_topicSuffix, "@{collector_default}") {
			if _collectorDefault == "" {
				if _metadata, _ok := _message.MessageMetaData.(*SyslogMessageMetaData); _ok {
					_collectorDefault = fmt.Sprintf ("%s/%s/%s/%s", _metadata.Protocol, _metadata.Node, _metadata.Service, _metadata.Level)
				} else if _metadata, _ok := _message.MessageMetaData.(*HttpMessageMetaData); _ok {
					_collectorDefault = fmt.Sprintf ("%s/%s", _metadata.Host, _metadata.Method)
				} else if _metadata, _ok := _message.MessageMetaData.(*MqttMessageMetaData); _ok {
					_collectorDefault = _metadata.Topic
				}
			}
			_replacements = append (_replacements, "@{collector_default}", _collectorDefault)
		}
		_replacer := strings.NewReplacer (_replacements ...)
		_topicSuffix = _replacer.Replace (_topicSuffix)
	}
	if _topicSuffix != "" {
		_topic += "/" + _topicSuffix
	}
	
	if _configuration.Debug {
		log.Printf ("[dd] [6f787eab]  output mqtt publishing message on topic `%s` (%d bytes)...\n", _topic, len (_buffer))
	}
	
	_cancelation := context.Background ()
	if _error := _client.Publish (_cancelation.Done (), _buffer, _topic); _error != nil {
		logError (_error, "[423309f9]  output mqtt failed to publish message;  ignoring!")
		return _error
	}
	
	return nil
}


