

package main


import "context"
import "encoding/json"
import "fmt"
import "log"
import "os"
import "sync"
import "syscall"
import "time"

import mqtt "github.com/pascaldekloe/mqtt"




type OutputMqttConfiguration struct {
	
	Identifier string
	ConnectTcp string
	Topic string
	Client string
	Username string
	Password string
	KeepAlive uint
	CleanSession bool
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
	
	_clientConfig := & mqtt.Config {
			AtLeastOnceMax : 16384,
			ExactlyOnceMax : 16384,
			PauseTimeout : 6 * time.Second,
		}
	
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
	_clientConfig.KeepAlive = uint16 (_configuration.KeepAlive)
	_clientConfig.CleanSession = _configuration.CleanSession
	
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
				log.Printf ("[ww] [9db18266]  output mqtt received message;  ignoring!\n")
			} else if _error == mqtt.ErrClosed {
				return
			} else {
				logError (_error, "[3b3287f9]  output mqtt failed to receive message;  retrying!")
				time.Sleep (DefaultOutputMqttRetry)
			}
		}
	} ()
	
	go func () () {
		for {
			time.Sleep (DefaultOutputMqttPing)
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
	
	if _configuration.Debug {
		log.Printf ("[dd] [6f787eab]  output mqtt publishing message (%d bytes)...\n", len (_buffer))
	}
	
	_cancelation := context.Background ()
	if _error := _client.Publish (_cancelation.Done (), _buffer, _configuration.Topic); _error != nil {
		logError (_error, "[423309f9]  output mqtt failed to publish message;  ignoring!")
		return _error
	}
	
	return nil
}


