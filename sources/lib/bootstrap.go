

package lib


import "log"
import "os"
import "os/signal"
import "sync"
import "syscall"
import "time"




type Flags struct {
	
	InputSyslog *InputSyslogFlags `group:"Input Syslog options"`
	InputHttp *InputHttpFlags `group:"Input HTTP options"`
	
	OutputStdout *OutputStdoutFlags `group:"Output STDOUT options"`
	OutputFile *OutputFileFlags `group:"Output file options"`
	
	InputMqtt *InputMqttFlags `group:"Input MQTT options"`
	OutputMqtt *OutputMqttFlags `group:"Output MQTT options"`
	
	Dequeue *DequeueFlags `group:"Queue options"`
	Parser *ParserFlags `group:"Parser options"`
	Global *GlobalFlags `group:"Global options"`
}


type GlobalFlags struct {
	
	Debug *FlagsBool `long:"debug" value-name:"{bool}"`
}


type MetaFlags struct {
	
	Help bool `short:"h" long:"help" no-ini:"-"`
	DumpFlags bool `long:"dump-flags" no-ini:"-"`
	DumpConfiguration bool `long:"dump-configuration" no-ini:"-"`
}




type Configuration struct {
	
	InputSyslog *InputSyslogConfiguration
	InputHttp *InputHttpConfiguration
	InputMqtt *InputMqttConfiguration
	
	OutputStdout *OutputStdoutConfiguration
	OutputFile *OutputFileConfiguration
	OutputMqtt *OutputMqttConfiguration
	
	Dequeue *DequeueConfiguration
	Parser *ParserConfiguration
	
	MessagesQueueSize uint
	Debug bool
}




func bootstrap () (error) {
	
	
	if DefaultGlobalDebug {
		log.Printf ("[ii] [69922ece]  configuring services...\n")
	}
	var _configuration *Configuration = nil
	if _configuration_0, _error := configure (os.Args[1:]); _error == nil {
		_configuration = _configuration_0
	} else {
		return _error
	}
	
	
	if _configuration.Debug {
		log.Printf ("[ii] [e1603153]  initializing services...\n")
	}
	
	_inputQueue := make (chan *CollectorMessage, _configuration.MessagesQueueSize)
	_outputQueues := make ([] chan<- *Message, 0)
	
	_mainSignalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
	_serviceSignalsQueues := make ([] chan os.Signal, 0)
	_exitGroup := & sync.WaitGroup {}
	
	
	signal.Notify (_mainSignalsQueue, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify (_mainSignalsQueue, syscall.SIGHUP)
	signal.Notify (_mainSignalsQueue, syscall.SIGUSR1, syscall.SIGUSR2)
	
	
	var _inputSyslogContext *InputSyslogContext = nil
	var _inputHttpContext *InputHttpContext = nil
	var _inputMqttContext *InputMqttContext = nil
	var _outputStdoutContext *OutputStdoutContext = nil
	var _outputFileContext *OutputFileContext = nil
	var _outputMqttContext *OutputMqttContext = nil
	var _parserContext *ParserContext = nil
	var _dequeueContext *DequeueContext = nil
	
	
	_wait := func () () {
			
			go func () () {
				for {
					log.Printf ("[ww] [cd90630d]  terminating services...\n")
					for _, _signalsQueue := range _serviceSignalsQueues {
						select {
							case _signalsQueue <- syscall.SIGTERM :
							default :
						}
					}
					time.Sleep (1 * time.Second)
				}
			} ()
			
			_exitGroup.Wait ()
			
			if _inputSyslogContext != nil {
				inputSyslogFinalize (_inputSyslogContext)
			}
			if _inputHttpContext != nil {
				inputHttpFinalize (_inputHttpContext)
			}
			if _inputMqttContext != nil {
				inputMqttFinalize (_inputMqttContext)
			}
			if _outputStdoutContext != nil {
				outputStdoutFinalize (_outputStdoutContext)
			}
			if _outputFileContext != nil {
				outputFileFinalize (_outputFileContext)
			}
			if _outputMqttContext != nil {
				outputMqttFinalize (_outputMqttContext)
			}
			if _parserContext != nil {
				parserFinalize (_parserContext)
			}
			if _dequeueContext != nil {
				dequeueFinalize (_dequeueContext)
			}
			
			if _configuration.Debug {
				log.Printf ("[ii] [b3181816]  terminated services!\n")
			}
		}
	
	defer _wait ()
	
	
	if _configuration.InputSyslog != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [1b82323e]  initializing input http...\n")
		}
		_configuration := _configuration.InputSyslog
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputSyslogInitialize (_configuration, _inputQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputSyslogContext = _context
		} else {
			return _error
		}
	}
	
	
	if _configuration.InputHttp != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [e0bab114]  initializing input http...\n")
		}
		_configuration := _configuration.InputHttp
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputHttpInitialize (_configuration, _inputQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputHttpContext = _context
		} else {
			return _error
		}
	}
	
	
	if _configuration.InputMqtt != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [18ba2a1b]  initializing input mqtt...\n")
		}
		_configuration := _configuration.InputMqtt
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputMqttInitialize (_configuration, _inputQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputMqttContext = _context
		} else {
			return _error
		}
	}
	
	
	if _configuration.OutputStdout != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [cf9ea565]  initializing output stdout...\n")
		}
		_configuration := _configuration.OutputStdout
		_outputQueue := make (chan *Message, _configuration.QueueSize)
		_outputQueues = append (_outputQueues, _outputQueue)
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := outputStdoutInitialize (_configuration, _outputQueue, _signalsQueue, _exitGroup); _error == nil {
			_outputStdoutContext = _context
		} else {
			return _error
		}
	}
	
	
	if _configuration.OutputFile != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [41085a24]  initializing output file...\n")
		}
		_configuration := _configuration.OutputFile
		_outputQueue := make (chan *Message, _configuration.QueueSize)
		_outputQueues = append (_outputQueues, _outputQueue)
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := outputFileInitialize (_configuration, _outputQueue, _signalsQueue, _exitGroup); _error == nil {
			_outputFileContext = _context
		} else {
			return _error
		}
	}
	
	
	if _configuration.OutputMqtt != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [8e41fe87]  initializing output mqtt...\n")
		}
		_configuration := _configuration.OutputMqtt
		_outputQueue := make (chan *Message, _configuration.QueueSize)
		_outputQueues = append (_outputQueues, _outputQueue)
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := outputMqttInitialize (_configuration, _outputQueue, _signalsQueue, _exitGroup); _error == nil {
			_outputMqttContext = _context
		} else {
			return _error
		}
	}
	
	
	{
		if _configuration.Debug {
			log.Printf ("[ii] [63ca1586]  initializing parser...\n")
		}
		_configuration := _configuration.Parser
		if _context, _error := parserInitialize (_configuration); _error == nil {
			_parserContext = _context
		} else {
			return _error
		}
	}
	
	
	{
		if _configuration.Debug {
			log.Printf ("[ii] [b86862c9]  initializing dequeue...\n")
		}
		_configuration := _configuration.Dequeue
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := dequeueInitialize (_configuration, _parserContext, _inputQueue, _outputQueues, _signalsQueue, _exitGroup); _error == nil {
			_dequeueContext = _context
		} else {
			return _error
		}
	}
	
	
	if _configuration.Debug {
		log.Printf ("[ii] [e5759817]  initialized services!\n")
	}
	
	
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
	
	
	return nil
}


