

package main


import "log"
import "os"
import "os/signal"
import "sync"
import "syscall"
import "time"





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
	if _configuration.InputSyslog != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [1b82323e]  initializing input http...\n")
		}
		_configuration := _configuration.InputSyslog
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputSyslogInitialize (_configuration, _inputQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputSyslogContext = _context
			defer inputSyslogFinalize (_inputSyslogContext)
		} else {
			return _error
		}
	}
	
	
	var _inputHttpContext *InputHttpContext = nil
	if _configuration.InputHttp != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [e0bab114]  initializing input http...\n")
		}
		_configuration := _configuration.InputHttp
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputHttpInitialize (_configuration, _inputQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputHttpContext = _context
			defer inputHttpFinalize (_inputHttpContext)
		} else {
			return _error
		}
	}
	
	
	var _inputMqttContext *InputMqttContext = nil
	if _configuration.InputMqtt != nil {
		if _configuration.Debug {
			log.Printf ("[ii] [18ba2a1b]  initializing input mqtt...\n")
		}
		_configuration := _configuration.InputMqtt
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := inputMqttInitialize (_configuration, _inputQueue, _signalsQueue, _exitGroup); _error == nil {
			_inputMqttContext = _context
			defer inputMqttFinalize (_inputMqttContext)
		} else {
			return _error
		}
	}
	
	
	var _outputStdoutContext *OutputStdoutContext = nil
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
			defer outputStdoutFinalize (_outputStdoutContext)
		} else {
			return _error
		}
	}
	
	
	var _outputFileContext *OutputFileContext = nil
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
			defer outputFileFinalize (_outputFileContext)
		} else {
			return _error
		}
	}
	
	
	var _outputMqttContext *OutputMqttContext = nil
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
			defer outputMqttFinalize (_outputMqttContext)
		} else {
			return _error
		}
	}
	
	
	var _parserContext *ParserContext = nil
	{
		if _configuration.Debug {
			log.Printf ("[ii] [63ca1586]  initializing parser...\n")
		}
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
		if _configuration.Debug {
			log.Printf ("[ii] [b86862c9]  initializing dequeue...\n")
		}
		_configuration := _configuration.Dequeue
		_signalsQueue := make (chan os.Signal, DefaultSignalsQueueSize)
		_serviceSignalsQueues = append (_serviceSignalsQueues, _signalsQueue)
		if _context, _error := dequeueInitialize (_configuration, _parserContext, _inputQueue, _outputQueues, _signalsQueue, _exitGroup); _error == nil {
			_dequeueContext = _context
			defer dequeueFinalize (_dequeueContext)
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
	
	
	go func () () {
		for {
			time.Sleep (1 * time.Second)
			log.Printf ("[ww] [cd90630d]  terminating services...\n")
			for _, _signalsQueue := range _serviceSignalsQueues {
				select {
					case _signalsQueue <- syscall.SIGTERM :
					default :
				}
			}
		}
	} ()
	
	
	_exitGroup.Wait ()
	
	if _configuration.Debug {
		log.Printf ("[ii] [b3181816]  terminated services!\n")
	}
	
	
	return nil
}


