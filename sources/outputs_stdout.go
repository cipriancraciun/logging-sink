

package main


import "fmt"
import "log"
import "os"
import "sync"
import "syscall"




type OutputStdoutConfiguration struct {
	
	JsonPretty bool
	JsonSequence bool
	Flush bool
	QueueSize uint
	Debug bool
}


type OutputStdoutContext struct {
	
	configuration *OutputStdoutConfiguration
	initialized bool
	
	file *os.File
	
	messagesQueue <-chan *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
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
	
	if _configuration.Debug {
		log.Printf ("[ii] [f168ffc9]  output stdout starting...\n")
	}
	
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
	
	_configuration := _context.configuration
	
	if _configuration.Debug {
		log.Printf ("[ii] [345aa7cc]  output stdout started;\n")
	}
	
	_stop : for {
		select {
			
			case _message := <- _context.messagesQueue :
				if _error := outputStdoutProcess (_context, _message); _error != nil {
					logError (_error, "[0c142768]  output stdout failed processing message;  ignoring!")
				}
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [bb274e9a]  output stdout interrupted by signal:  `%s`!  terminating!\n", _signal)
						}
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[ee] [68802f72]  output stdout interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [84cc1079]  output stdout finalizing...\n")
	}
	if _error := outputStdoutFinalize (_context); _error != nil {
		logError (_error, "[021ed52c]  output stdout failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [7d12bc82]  output stdout terminated;\n")
	return nil
}




func outputStdoutProcess (_context *OutputStdoutContext, _message *Message) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[e360d509]  output stdout is not initialized!")
	}
	
	_configuration := _context.configuration
	
	return outputStreamProcess (_context.file, _message, _configuration.JsonPretty, _configuration.JsonSequence, _configuration.Flush)
}


