

package lib


import "fmt"
import "log"
import "os"
import "sync"
import "syscall"
import "time"




type DequeueFlags struct {
	
	MessagesQueueSize *uint `long:"messages-queue" value-name:"{count}"`
	
	ReportInterval *time.Duration `long:"report-interval" value-name:"{duration}"`
	ReportCounter *uint `long:"report-messages" value-name:"{count}"`
	
	Debug *FlagsBool  //  TODO?
}


type DequeueConfiguration struct {
	
	ReportInterval time.Duration
	ReportCounter uint
	Debug bool
	
	TickerInterval time.Duration
}


type DequeueContext struct {
	
	configuration *DequeueConfiguration
	parser *ParserContext
	initialized bool
	
	sequence uint64
	dropped uint64
	overflown uint64
	
	inboundQueue <-chan *CollectorMessage
	outboundQueues [] chan<- *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




func dequeueInitialize (_configuration *DequeueConfiguration, _parser *ParserContext, _inboundQueue <-chan *CollectorMessage, _outboundQueues [] chan<- *Message, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*DequeueContext, error) {
	
	_context := & DequeueContext {
			configuration : _configuration,
			parser : _parser,
			initialized : true,
			inboundQueue : _inboundQueue,
			outboundQueues : _outboundQueues,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	if _configuration.Debug {
		log.Printf ("[ii] [e686224a]  dequeue starting...\n")
	}
	
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
	_context.inboundQueue = nil
	_context.outboundQueues = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	
	_exitGroup.Done ()
	
	return nil
}




func dequeueLooper (_context *DequeueContext) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[2db95b48]  dequeue is not initialized!")
	}
	
	_configuration := _context.configuration
	_ticker := time.NewTicker (_configuration.TickerInterval)
	
	_lastReportTimestamp := time.Now ()
	_lastReportSequence := uint64 (0)
	
	if _configuration.Debug {
		log.Printf ("[ii] [425c288e]  dequeue started receiving messages...\n")
	}
	
	for {
		
		if _configuration.Debug {
			log.Printf ("[ii] [5cedbf0d]  dequeue waiting to receive message #%d...\n", _context.sequence + 1)
		}
		
		var _message *CollectorMessage = nil
		_shouldStop := false
		_shouldReport := false
		
		select {
			
			case _message = <- _context.inboundQueue :
				if _message == nil {
					_shouldStop = true
					_shouldReport = true
				}
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [61daa6e2]  dequeue interrupted by signal:  `%s`;  terminating!\n", _signal)
						}
						_shouldStop = true
						_shouldReport = true
					
					case syscall.SIGHUP :
						_shouldReport = true
					
					default :
						log.Printf ("[ee] [e883f5fd]  dequeue interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
			
			case <- _ticker.C :
				if _configuration.Debug {
					log.Printf ("[ii] [55e14446]  dequeue timedout waiting to receive message #%d;  retrying!\n", _context.sequence + 1)
				}
		}
		
		_timestamp := time.Now ()
		
		if _message != nil {
			_context.sequence += 1
			if _error := dequeueProcess (_context, _message); _error != nil {
				logError (_error, fmt.Sprintf ("[46d8f692]  dequeue failed processing the message #%d;  ignoring!", _context.sequence))
			}
			if (_context.sequence % uint64 (_configuration.ReportCounter)) == 0 {
				_shouldReport = true
			}
		}
		
		if _timestamp.Sub (_lastReportTimestamp) >= _configuration.ReportInterval {
			_shouldReport = true
		}
		
		if _shouldReport {
			_deltaTimestamp := _timestamp.Sub (_lastReportTimestamp) .Seconds () + 0.0000000001
			_deltaSequence := _context.sequence - _lastReportSequence
			_deltaSpeed := float64 (_deltaSequence) / _deltaTimestamp
			if _deltaSequence > 0 {
				log.Printf ("[ii] [5cf68979]  processed %d K messages (currently %d at %.2f m/s, in total %d, dropped %d, overflown %d);\n", _context.sequence / 1000, _deltaSequence, _deltaSpeed, _context.sequence, _context.dropped, _context.overflown)
			} else {
				log.Printf ("[ii] [9eea1474]  processed %d K messages (in total %d, dropped %d, overflown %d);\n", _context.sequence / 1000, _context.sequence, _context.dropped, _context.overflown)
			}
			_lastReportTimestamp = _timestamp
			_lastReportSequence = _context.sequence
		}
		
		if _shouldStop {
			break
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [068b224e]  dequeue stopped receiving messages;\n")
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [d39d8157]  dequeue finalizing...\n")
	}
	if _error := dequeueFinalize (_context); _error != nil {
		logError (_error, "[b31a98f6]  dequeue failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [c3dabaf5]  dequeue terminated;\n")
	return nil
}




func dequeueProcess (_context *DequeueContext, _collectorMessage *CollectorMessage) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[1740da8a]  dequeue is not initialized!")
	}
	
	_configuration := _context.configuration
	
	var _message *Message
	if _message_0, _error := parserProcess (_context.parser, _collectorMessage, _context.sequence); _error == nil {
		_message = _message_0
	} else {
		return _error
	}
	
	if _message != nil {
		for _, _outboundQueue := range _context.outboundQueues {
			select {
				case _outboundQueue <- _message :
				default :
					_context.overflown += 1
					if _configuration.Debug {
						log.Printf ("[ww] [24c5974b]  dequeue overflown pushing the message #%d;\n", _context.sequence)
					}
			}
		}
	} else {
		_context.dropped += 1
	}
	
	if _configuration.Debug {
		if _message != nil {
			log.Printf ("[ii] [4e4ef11d]  dequeue succeeded processing the message #%d;\n", _context.sequence)
		} else {
			log.Printf ("[ii] [b3d065cf]  dequeue dropped processing the message #%d;\n", _context.sequence)
		}
	}
	
	return nil
}


