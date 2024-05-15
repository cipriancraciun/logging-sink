

package lib


import "encoding/json"
import "fmt"
import "io/ioutil"
import "log"
import "mime"
import "net"
import "net/http"
import "os"
import "strings"
import "sync"
import "syscall"
import "time"




type InputHttpFlags struct {
	
	Enabled *FlagsBool `long:"input-http-enabled" value-name:"{bool}"`
	Identifier *string `long:"input-http-identifier" value-name:"{identifier}"`
	ListenTcp *string `long:"input-http-listen-tcp" value-name:"{ip}:{port}"`
	Timeout *time.Duration `long:"input-http-timeout" value-name:"{duration}"`
	AllowedPath *string `long:"input-http-allowed-path" value-name:"{path}"`
	ParseJson *FlagsBool `long:"input-http-parse-json" value-name:"{bool}"`
	ParseXml *FlagsBool `long:"input-http-parse-xml" value-name:"{bool}"`
	Debug *FlagsBool `long:"input-http-debug" value-name:"{bool}"`
}


type InputHttpConfiguration struct {
	
	Identifier string
	ListenTcp string
	Timeout time.Duration
	AllowedPath string
	ParseJson bool
	ParseXml bool
	Debug bool
}


type InputHttpContext struct {
	
	configuration *InputHttpConfiguration
	initialized bool
	
	server *http.Server
	
	messagesQueue chan<- *CollectorMessage
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




func inputHttpInitialize (_configuration *InputHttpConfiguration, _messagesQueue chan<- *CollectorMessage, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*InputHttpContext, error) {
	
	_server := & http.Server {}
	
	_listening := false
	if _configuration.ListenTcp != "" {
		if _configuration.Debug {
			log.Printf ("[ii] [e60673cd]  input http listening on TCP at `%s`...\n", _configuration.ListenTcp)
		}
		_server.Addr = _configuration.ListenTcp
		_listening = true
	}
	
	if !_listening {
		return nil, fmt.Errorf ("[20732489]  input http has no listeners configured!")
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [8e924835]  input http using timeout of `%s`...\n", _configuration.Timeout)
	}
	_server.ReadTimeout = _configuration.Timeout
	_server.WriteTimeout = _configuration.Timeout
	_server.IdleTimeout = _configuration.Timeout
	
	if _configuration.Debug {
		log.Printf ("[ii] [6ff0ba51]  input http starting...\n")
	}
	
	_context := & InputHttpContext {
			configuration : _configuration,
			initialized : true,
			server : _server,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	_server.Handler = (*InputHttpHandler) (_context)
	
	_listenError := make (chan error)
	go func () () {
		_listenError <- _server.ListenAndServe ()
	} ()
	time.Sleep (100 * time.Millisecond)
	select {
		case _error := <- _listenError :
			return nil, _error
		default :
	}
	
	_exitGroup.Add (1)
	
	go inputHttpLooper (_context)
	
	return _context, nil
}




func inputHttpFinalize (_context *InputHttpContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	var _error error = nil
	if _context.server != nil {
		if _context.configuration.Debug {
			log.Printf ("[ii] [1fecdb14]  input http closing...\n")
		}
		_error = _context.server.Close ()
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




func inputHttpLooper (_context *InputHttpContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_configuration := _context.configuration
	
	if _configuration.Debug {
		log.Printf ("[ii] [e00a19dd]  input http started;\n")
	}
	
	_stop : for {
		select {
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [8504a17a]  input http interrupted by signal:  `%s`;  terminating!\n", _signal)
						}
						break _stop
					
					case syscall.SIGHUP :
					
					default :
						log.Printf ("[ee] [01156c7f]  input http interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [3b0714cb]  input http finalizing...\n")
	}
	if _error := inputHttpFinalize (_context); _error != nil {
		logError (_error, "[707272da]  input http failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [f65a6d1a]  input http terminated;\n")
	return nil
}




type InputHttpHandler InputHttpContext

func (_context_0 *InputHttpHandler) ServeHTTP (_response http.ResponseWriter, _request *http.Request) () {
	
	if (_request.RequestURI == "/__/heartbeat") {
		_response.Header () ["Content-Type"] = []string { "text/plain" }
		_response.WriteHeader (200)
		_response.Write ([]byte ("OK\n"))
		return
	}
	
	_context := (*InputHttpContext) (_context_0)
	
	if _error := inputHttpProcess (_context, _request); _error == nil {
		_response.Header () ["Content-Type"] = []string { "text/plain" }
		_response.WriteHeader (200)
		_response.Write ([]byte ("OK\n"))
	} else {
		logError (_error, "[61095a98]  input http failed to process message;  ignoring!")
		_response.Header () ["Content-Type"] = []string { "text/plain" }
		_response.WriteHeader (500)
		_response.Write ([]byte ("NOK\n"))
	}
}




func inputHttpProcess (_context *InputHttpContext, _request *http.Request) (error) {
	
	_configuration := _context.configuration
	
	_timestamp := time.Now ()
	
	var _messageRaw []byte
	if _messageRaw_0, _error := inputHttpRequestExtractData (_context, _request); _error == nil {
		_messageRaw = _messageRaw_0
	} else {
		logError (_error, "[76b2f6fc]  input http failed reading request body;  ignoring!")
		return nil
	}
	
	_messageSha256 := generateMessageSha256 (_messageRaw)
	
	_messageParseable := true
	
	if len (_request.TransferEncoding) != 0 {
		log.Printf ("[ww] [2ed4bb6]  input http failed accepting transfer encoding:  unsupported encoding `%#v`;  ignoring and aborting parsing!\n", _request.TransferEncoding)
		_messageParseable = false
	}
	
	_messageContentEncoding := _request.Header.Get ("Content-Encoding")
	//  NOTE:  See: https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding
	switch _messageContentEncoding {
		case "", "identity" :
			_messageContentEncoding = ""
		case
				"gzip", "x-gzip",
				"deflate",
				"compress", "x-compress",
				"br" :
			log.Printf ("[ww] [060ec0e1]  input http failed accepting content encoding:  unsupported encoding `%s`;  ignoring and aborting parsing!\n", _messageContentEncoding)
			_messageParseable = false
		default :
			log.Printf ("[ee] [0369add3]  input http failed accepting content encoding:  unknown encoding `%s`;  ignoring and aborting parsing!\n", _messageContentEncoding)
			_messageParseable = false
	}
	
	_messageContentType := _request.Header.Get ("Content-Type")
	var _messageContentTypeParameters map[string]string = nil
	if _messageContentType != "" {
		if _type, _parameters, _error := mime.ParseMediaType (_messageContentType); _error == nil {
			_messageContentType = _type
			_messageContentTypeParameters = _parameters
		} else {
			logError (_error, "[508c527b]  input http failed accepting content type:  invalid format;  ignoring and aborting parsing!")
			_messageContentType = ""
			_messageParseable = false
		}
	} else {
		log.Printf ("[ww] [25f3b227]  input http failed accepting content type:  missing;  ignoring and aborting parsing!\n")
			_messageParseable = false
	}
	
	var _messageText string = ""
	var _messageJson json.RawMessage = nil
	
	if _messageParseable {
		switch _messageContentType {
			case "text/plain", "application/json", "application/xml" :
				if _text, _valid := parseMessageText (_messageRaw); _valid {
					_messageText = _text
				} else {
					log.Printf ("[ww] [9d938d82]  input http failed accepting body:  invalid UTF-8;  ignoring and aborting parsing!\n")
					_messageParseable = false
				}
			default :
				_messageParseable = false
		}
	}
	
	if _messageParseable {
		switch _messageContentType {
			case "application/json", "application/xml" :
				_messageText = strings.TrimSpace (_messageText)
				if _messageText == "" {
					log.Printf ("[ww] [f49a6c18]  input failed accepting body:  empty (if ignoring whitespaces);  ignoring and aborting parsing!")
					_messageParseable = false
				}
		}
	}
	
	if _messageParseable {
		switch _messageContentType {
			
			case "text/plain" :
				{} // NOP
			
			case "application/json" :
				if _configuration.ParseJson {
					if _json, _error := parseMessageJson (_messageText); _error == nil {
						_messageJson = _json
					} else {
						logError (_error, "[fb140c77]  input http failed accepting body:  invalid JSON format;  ignoring and aborting parsing!")
						_messageParseable = false
					}
				}
			
			case "application/xml" :
				if _configuration.ParseXml {
					if _json, _error := parseMessageXml (_messageText); _error == nil {
						_messageJson = _json
					} else {
						logError (_error, "[ffb58358]  input http failed accepting body:  invalid XML format;  ignoring and aborting parsing!")
						_messageParseable = false
					}
				}
			
			default :
				log.Printf ("[ww] [b1a47bf8]  input http failed accepting header `Content-Type`:  unsupported encoding `%s`;  ignoring and aborting parsing!\n", _messageContentType)
				_messageParseable = false
		}
	}
	
	_remoteAddr, _ := net.ResolveTCPAddr ("tcp", _request.RemoteAddr)
	//  FIXME:  Configure trusting `X-Forwarded-For` headers!
	//  FIXME:  Implement acording to <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For>
	if _forwardedFor_0 := _request.Header.Get ("X-Forwarded-For"); _forwardedFor_0 != "" {
		_forwardedFor_1 := strings.Split (_forwardedFor_0, ",")
		for len (_forwardedFor_1) > 0 {
			_forwardedFor_2 := _forwardedFor_1[len (_forwardedFor_1) - 1]
			_forwardedFor_2 = strings.TrimSpace (_forwardedFor_2)
			if _forwardedFor_2 != "" {
				_forwardedFor_3 := net.ParseIP (_forwardedFor_2)
				if _forwardedFor_3 != nil {
					_remoteAddr = & net.TCPAddr {
							IP : _forwardedFor_3,
							Port : 0,
						}
					break
				}
			}
			_forwardedFor_1 = _forwardedFor_1[0 : len (_forwardedFor_1) - 1]
		}
	}
	
	_collectorMessage := & CollectorMessage {
			CollectorType : HttpCollectorType,
			CollectorIdentifier : _configuration.Identifier,
			CollectorTimestamp : _timestamp,
			MessageRaw : _messageRaw,
			MessageSha256 : _messageSha256,
			MessageText : _messageText,
			MessageJson : _messageJson,
			MessageMetaData : & HttpMessageMetaData {
					Schema : HttpMessageMetaDataSchema,
					Protocol : strings.ToLower (_request.Proto),
					Url : _request.URL.String (),
					UrlRaw : _request.RequestURI,
					Host : strings.ToLower (_request.Host),
					Method : strings.ToLower (_request.Method),
					Path : _request.URL.Path,
					Query : _request.URL.Query (),
					QueryRaw : _request.URL.RawQuery,
					Headers : inputHttpRequestExtractHeaders (_context, _request.Header),
					Trailers : inputHttpRequestExtractHeaders (_context, _request.Trailer),
					RemoteIp : _remoteAddr.IP.String (),
					RemotePort : uint16 (_remoteAddr.Port),
					ContentType : _messageContentType,
					ContentTypeParameters : _messageContentTypeParameters,
					ContentEncoding : _messageContentEncoding,
					ContentLength : _request.ContentLength,
					TransferEncoding : inputHttpRequestExtractHeaderValue (_context, _request.TransferEncoding),
				},
		}
	
	_context.messagesQueue <- _collectorMessage
	
	return nil
}




func inputHttpRequestExtractData (_context *InputHttpContext, _request *http.Request) ([]byte, error) {
	
	var _data []byte
	if _data_0, _error := ioutil.ReadAll (_request.Body); _error == nil {
		_data = _data_0
	} else {
		return nil, _error
	}
	
	if len (_data) == 0 {
		_data = nil
	}
	
	return _data, nil
}




func inputHttpRequestExtractHeaders (_context *InputHttpContext, _httpHeaders http.Header) (HttpMessageHeaders) {
	
	_headers := make (map[string]HttpMessageHeaderValue, len (_httpHeaders))
	
	for _identifier, _values := range _httpHeaders {
		_identifier = strings.ToLower (_identifier)
		_headers[_identifier] = inputHttpRequestExtractHeaderValue (_context, _values)
	}
	
	return _headers
}

func inputHttpRequestExtractHeaderValue (_context *InputHttpContext, _values []string) (HttpMessageHeaderValue) {
	
	if _values == nil {
		return nil
	}
	
	switch len (_values) {
		case 0 :
			return nil
		case 1 :
			return _values[0]
		default :
			return _values
	}
}


