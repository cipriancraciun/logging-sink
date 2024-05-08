

package main


import "context"
import "crypto/sha256"
import "encoding/json"
import "encoding/hex"
import "fmt"
import "log"
import "os"
import "strings"
import "sync"
import "sync/atomic"
import "syscall"
import "time"
import "unicode/utf8"

import mqtt "github.com/pascaldekloe/mqtt"




type InputMqttConfiguration struct {
	
	Identifier string
	ConnectTcp string
	Topic string
	Client string
	Username string
	Password string
	KeepAlive uint
	CleanSession bool
	ParseJson bool
	Debug bool
}


type InputMqttContext struct {
	
	configuration *InputMqttConfiguration
	initialized bool
	
	client *mqtt.Client
	
	messagesQueue chan<- *CollectorMessage
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




func inputMqttInitialize (_configuration *InputMqttConfiguration, _messagesQueue chan<- *CollectorMessage, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*InputMqttContext, error) {
	
	_clientConfig := & mqtt.Config {
			AtLeastOnceMax : 16384,
			ExactlyOnceMax : 16384,
			PauseTimeout : 6 * time.Second,
		}
	
	_connecting := false
	if _configuration.ConnectTcp != "" {
		if _configuration.Debug {
			log.Printf ("[ii] [5982727d]  input mqtt connecting on TCP at `%s`...\n", _configuration.ConnectTcp)
		}
		_clientConfig.Dialer = mqtt.NewDialer ("tcp", _configuration.ConnectTcp)
		_connecting = true
	}
	
	if !_connecting {
		return nil, fmt.Errorf ("[6acc487a]  input mqtt has no connections configured!")
	}
	
	_clientId := _configuration.Client
	_clientConfig.UserName = _configuration.Username
	_clientConfig.Password = []byte (_configuration.Password)
	_clientConfig.KeepAlive = uint16 (_configuration.KeepAlive)
	_clientConfig.CleanSession = _configuration.CleanSession
	
	if _configuration.Debug {
		log.Printf ("[ii] [dd4a9562]  input mqtt starting...\n")
	}
	
	var _client *mqtt.Client
	if _client_0, _error := mqtt.VolatileSession (_clientId, _clientConfig); _error == nil {
		_client = _client_0
	} else {
		logError (_error, "[e91ff095]  input mqtt failed to connect;  aborting!")
		return nil, _error
	}
	
	_context := & InputMqttContext {
			configuration : _configuration,
			initialized : true,
			client : _client,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	_exitGroup.Add (1)
	
	go inputMqttLooper (_context)
	
	return _context, nil
}




func inputMqttFinalize (_context *InputMqttContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	var _error error = nil
	if _context.client != nil {
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




func inputMqttLooper (_context *InputMqttContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_configuration := _context.configuration
	_client := _context.client
	
	if _configuration.Debug {
		log.Printf ("[ii] [e4813408]  input mqtt started;\n")
	}
	
	var _subscribed atomic.Bool
	
	go func () () {
		for {
			if _configuration.Debug {
				log.Printf ("[ii] [626d4bad]  input mqtt receiving message...\n")
			}
			_message, _topic, _error := _client.ReadSlices ()
			if _error == nil {
				if _configuration.Debug {
					log.Printf ("[ii] [9db18266]  input mqtt received message;\n")
				}
				if _error := inputMqttProcess (_context, _topic, _message); _error != nil {
					logError (_error, "[9df3af2c]  input mqtt failed to process message;  ignoring!")
				}
			} else if _error == mqtt.ErrClosed {
				return
			} else {
				logError (_error, "[63f050f6]  input mqtt failed to receive message;  retrying!")
				_subscribed.Store (false)
				time.Sleep (DefaultInputMqttRetry)
			}
		}
	} ()
	
	go func () () {
		for {
			for {
				_clientTopics := []string { _configuration.Topic }
				time.Sleep (100 * time.Millisecond)
				_cancelation := context.Background ()
				if _configuration.Debug {
					for _, _clientTopic := range _clientTopics {
						log.Printf ("[ii] [8981a020]  input mqtt subscribing with `%s`...\n", _clientTopic)
					}
				}
				_subscribed.Store (true)
				if _error := _client.SubscribeLimitAtLeastOnce (_cancelation.Done (), _clientTopics ...); _error == nil {
					if _configuration.Debug {
						log.Printf ("[ii] [6bcb805b]  input mqtt subscribed;\n")
					}
					break
				} else if _error == mqtt.ErrClosed {
					return
				} else {
					logError (_error, "[bcefba57]  input mqtt failed to subscribe;  retrying!")
					continue
				}
			}
			for {
				if ! _subscribed.Load () {
					break
				}
				time.Sleep (DefaultInputMqttPing)
				if ! _subscribed.Load () {
					break
				}
				_cancelation := context.Background ()
				if _configuration.Debug {
					log.Printf ("[ii] [e4cd88ca]  input mqtt pinging...\n")
				}
				if _error := _client.Ping (_cancelation.Done ()); _error == nil {
					if _configuration.Debug {
						log.Printf ("[ii] [e2038eb6]  input mqtt pinged;\n")
					}
					continue
				} else if _error == mqtt.ErrClosed {
					return
				} else {
					logError (_error, "[4859935a]  input mqtt failed to ping;  retrying!")
					_subscribed.Store (false)
					break
				}
			}
		}
	} ()
	
	_stop : for {
		select {
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [db0e7516]  input mqtt interrupted by signal:  `%s`;  terminating!\n", _signal)
						}
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[ee] [56a2dcc2]  input mqtt interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [ebc2cbbb]  input mqtt finalizing...\n")
	}
	if _error := inputMqttFinalize (_context); _error != nil {
		logError (_error, "[a301ec7e]  input mqtt failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [dba32154]  input mqtt terminated;\n")
	return nil
}




func inputMqttProcess (_context *InputMqttContext, _topicRaw []byte, _messageRaw []byte) (error) {
	
	_configuration := _context.configuration
	
	var _topic string = ""
	if utf8.Valid (_topicRaw) {
		_topic = string (_topicRaw)
		_topicRaw = nil
	}
	
	_messageSha256Raw := sha256.Sum256 (_messageRaw)
	_messageSha256 := hex.EncodeToString (_messageSha256Raw[:])
	
	var _messageText string
	if utf8.Valid (_messageRaw) {
		_messageText = string (_messageRaw)
	}
	
	var _messageJson json.RawMessage = nil
	if _configuration.ParseJson && (_messageText != "") {
		_messageText_0 := strings.TrimSpace (_messageText)
		if strings.HasPrefix (_messageText_0, "{") && strings.HasSuffix (_messageText_0, "}") {
			if _error := json.Unmarshal ([]byte (_messageText_0), &_messageJson); _error == nil {
				// NOP
			}
		}
	}
	
	_collectorMessage := & CollectorMessage {
			CollectorType : MqttCollectorType,
			CollectorIdentifier : _configuration.Identifier,
			MessageRaw : _messageRaw,
			MessageSha256 : _messageSha256,
			MessageText : _messageText,
			MessageJson : _messageJson,
			MessageMetaData : & MqttMessageMetaData {
					Schema : MqttMessageMetaDataSchema,
					Topic : _topic,
				},
		}
	
	_context.messagesQueue <- _collectorMessage
	
	return nil
}


