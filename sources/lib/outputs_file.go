

package lib


import "crypto/rand"
import "encoding/json"
import "fmt"
import "log"
import "os"
import "os/exec"
import "path"
import "path/filepath"
import "sync"
import "syscall"
import "time"




type OutputFileConfiguration struct {
	
	CurrentStorePath string
	CurrentSymlinkPath string
	ArchivedStorePath string
	ArchivedCompressCommand []string
	ArchivedCompressSuffix string
	CurrentPrefix string
	ArchivedPrefix string
	CurrentSuffix string
	ArchivedSuffix string
	CurrentTimestamp string
	ArchivedTimestamp string
	Messages uint
	Timeout time.Duration
	JsonPretty bool
	JsonSequence bool
	Flush bool
	StoreMode os.FileMode
	FileMode os.FileMode
	TickerInterval time.Duration
	QueueSize uint
	Debug bool
}


type OutputFileContext struct {
	
	configuration *OutputFileConfiguration
	initialized bool
	
	nowTimestamp time.Time
	nowTimestampToken string
	
	currentTimestamp time.Time
	currentTimestampToken string
	currentMessages uint
	currentCurrentPath string
	currentArchivedPath string
	currentFile *os.File
	
	messagesQueue <-chan *Message
	signalsQueue <-chan os.Signal
	exitGroup *sync.WaitGroup
}




func outputFileInitialize (_configuration *OutputFileConfiguration, _messagesQueue <-chan *Message, _signalsQueue <-chan os.Signal, _exitGroup *sync.WaitGroup) (*OutputFileContext, error) {
	
	_context := & OutputFileContext {
			configuration : _configuration,
			initialized : true,
			messagesQueue : _messagesQueue,
			signalsQueue : _signalsQueue,
			exitGroup : _exitGroup,
		}
	
	if _configuration.Debug {
		log.Printf ("[ii] [83c65034]  output file starting...\n")
	}
	
	_exitGroup.Add (1)
	
	go outputFileLooper (_context)
	
	return _context, nil
}




func outputFileFinalize (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_error := outputFileClose (_context, true)
	
	_exitGroup := _context.exitGroup
	
	_context.initialized = false
	_context.messagesQueue = nil
	_context.signalsQueue = nil
	_context.exitGroup = nil
	
	_exitGroup.Done ()
	
	return _error
}




func outputFileLooper (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return nil
	}
	
	_configuration := _context.configuration
	
	if _configuration.Debug {
		log.Printf ("[ii] [10354775]  output file started;\n")
	}
	
	_ticker := time.NewTicker (_configuration.TickerInterval)
	
	_stop : for {
		select {
			
			case _message := <- _context.messagesQueue :
				outputFileTimestamp (_context)
				if _error := outputFileProcess (_context, _message); _error != nil {
					logError (_error, "[5fd6c601]  output file failed processing message;  ignoring!")
				}
			
			case _signal := <- _context.signalsQueue :
				switch _signal {
					
					case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT :
						if _configuration.Debug {
							log.Printf ("[ww] [c3f6650e]  output file interrupted by signal:  `%s`!  terminating!\n", _signal)
						}
						break _stop
					
					case syscall.SIGHUP :
						if _configuration.Debug {
							log.Printf ("[ii] [8198be0d]  output file interrupted by signal:  `%s`!  flushing...\n", _signal)
						}
						if _error := outputFileClose (_context, false); _error != nil {
							logError (_error, "[7017a4da]  output file failed to flush;  ignoring!")
						}
					
					default :
						log.Printf ("[ee] [3b5a9896]  output file interrupted by unexpected signal:  `%s`;  ignoring!\n", _signal)
				}
			
			case <- _ticker.C :
				outputFileTimestamp (_context)
				if _error := outputFileClosePerhaps (_context); _error != nil {
					logError (_error, "[9bc52216]  output file failed to flush;  ignoring!")
				}
		}
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [c0cd4992]  output file finalizing...\n")
	}
	if _error := outputFileFinalize (_context); _error != nil {
		logError (_error, "[86400d3b]  output file failed to finalize;  ignoring!")
		return _error
	}
	
	log.Printf ("[ii] [cdecc5a4]  output file terminated;\n")
	return nil
}




func outputFileProcess (_context *OutputFileContext, _message *Message) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[a73865e2]  output file is not initialized!")
	}
	
	_configuration := _context.configuration
	
	if _error := outputFileClosePerhaps (_context); _error != nil {
		logError (_error, "")
	}
	if _error := outputFileOpen (_context); _error != nil {
		logError (_error, "")
	}
	
	_context.currentMessages += 1
	
	if _context.currentFile != nil {
		return outputStreamProcess (_context.currentFile, _message, _configuration.JsonPretty, _configuration.JsonSequence, _configuration.Flush)
	} else {
		return fmt.Errorf ("[eb1083ab]  output file is not opened!")
	}
}




func outputFileTimestamp (_context *OutputFileContext) () {
	
	_timestamp := time.Now ()
	_timestampToken := _timestamp.Format (_context.configuration.CurrentTimestamp)
	
	_context.nowTimestamp = _timestamp
	_context.nowTimestampToken = _timestampToken
}




func outputFileOpen (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[32867341]  output file is not initialized!")
	}
	if _context.currentFile != nil {
		return nil
	}
	
	_configuration := _context.configuration
	
	_context.currentTimestamp = _context.nowTimestamp
	_context.currentTimestampToken = _context.nowTimestampToken
	_context.currentMessages = 0
	
	_randomToken := make ([]byte, 10)
	rand.Read (_randomToken)
	
	_context.currentCurrentPath = fmt.Sprintf (
			"%s%c%s%s-%06x%06x%10x%s",
			_configuration.CurrentStorePath,
			os.PathSeparator,
			_configuration.CurrentPrefix,
			_context.nowTimestampToken,
			_context.nowTimestamp.Unix () & 0xffffff,
			os.Getpid () & 0xffffff,
			_randomToken,
			_configuration.CurrentSuffix,
		)
	
	_context.currentArchivedPath = fmt.Sprintf (
			"%s%c%s%s-%06x%06x%10x%s",
			_configuration.ArchivedStorePath,
			os.PathSeparator,
			_configuration.ArchivedPrefix,
			_context.nowTimestamp.Format (_configuration.ArchivedTimestamp),
			_context.nowTimestamp.Unix () & 0xffffff,
			os.Getpid () & 0xffffff,
			_randomToken,
			_configuration.ArchivedSuffix,
		)
	
	if _error := os.MkdirAll (path.Dir (_context.currentCurrentPath), _configuration.StoreMode); _error != nil {
		log.Printf ("[ee] [9e694a9c]  output file failed opening current `%s` (mkdir);  ignoring!\n", _context.currentCurrentPath)
		logError (_error, "")
	}
	if _file, _error := os.OpenFile (_context.currentCurrentPath, os.O_CREATE | os.O_EXCL | os.O_WRONLY | os.O_APPEND, _configuration.FileMode); _error == nil {
		if _configuration.Debug {
			log.Printf ("[ii] [ffb1feda]  output file succeeded opening current `%s`;\n", _context.currentCurrentPath)
		}
		_context.currentFile = _file
	} else {
		log.Printf ("[ee] [27432827]  output file failed opening current `%s` (open);  ignoring!\n", _context.currentCurrentPath)
		logError (_error, "")
		_context.currentFile = nil
	}
	
	if _configuration.CurrentSymlinkPath != "" {
		if _error := os.Remove (_configuration.CurrentSymlinkPath); (_error != nil) && ! os.IsNotExist (_error) {
			logError (_error, "[fb4f5f7b]  output file failed symlink-ing current (unlink);  ignoring!")
		}
		if _relativePath, _error := filepath.Rel (path.Dir (_configuration.CurrentSymlinkPath), _context.currentCurrentPath); _error != nil {
			logError (_error, "[a578ba45]  output file failed symlink-ing current (relpath);  ignoring!")
		} else if _error := os.Symlink (_relativePath, _configuration.CurrentSymlinkPath); _error != nil {
			logError (_error, "[f0ccc0b5]  output file failed symlink-ing current (relpath);  ignoring!")
		}
	}
	
	return nil
}




func outputFileClosePerhaps (_context *OutputFileContext) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[96c62f00]  output file is not initialized!")
	}
	if _context.currentFile == nil {
		return nil
	}
	
	_configuration := _context.configuration
	
	_shouldClose := false
	if ! _shouldClose && (_context.currentMessages >= _configuration.Messages) {
		if _configuration.Debug {
			log.Printf ("[ii] [6608f486]  output file reached maximum messages count limit;\n")
		}
		_shouldClose = true
	}
	if ! _shouldClose && (_context.nowTimestamp.Sub (_context.currentTimestamp) >= _configuration.Timeout) {
		if _configuration.Debug {
			log.Printf ("[ii] [963bf22e]  output file reached maximum file age limit;\n")
		}
		_shouldClose = true
	}
	if ! _shouldClose && (_context.currentTimestampToken != _context.nowTimestampToken) {
		if _configuration.Debug {
			log.Printf ("[ii] [214f5ea7]  output file changed timestamp token;\n")
		}
		_shouldClose = true
	}
	
	if _shouldClose {
		return outputFileClose (_context, false)
	} else {
		return nil
	}
}




func outputFileClose (_context *OutputFileContext, _wait bool) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[7ac83fe5]  output file is not initialized!")
	}
	if _context.currentFile == nil {
		return nil
	}
	
	_configuration := _context.configuration
	
	if _error := _context.currentFile.Close (); _error == nil {
		if _configuration.Debug {
			log.Printf ("[ii] [b8e7c1d1]  output file succeeded closing previous `%s`;\n", _context.currentCurrentPath)
		}
	} else {
		log.Printf ("[ee] [c1b80cc7]  output file failed closing previous `%s`;  ignoring!\n", _context.currentCurrentPath)
		logError (_error, "")
	}
	
	if _error := os.Remove (_configuration.CurrentSymlinkPath); (_error != nil) && ! os.IsNotExist (_error) {
		logError (_error, "[5df85030]  output file failed symlink-ing current (unlink);  ignoring!")
	}
	
	if _context.currentCurrentPath != _context.currentArchivedPath {
		if _error := os.MkdirAll (path.Dir (_context.currentArchivedPath), _configuration.StoreMode); _error != nil {
			log.Printf ("[ee] [0febdcf9]  output file failed renaming previous `%s` (mkdir);  ignoring!\n", _context.currentArchivedPath)
			logError (_error, "")
		}
		if _error := os.Rename (_context.currentCurrentPath, _context.currentArchivedPath); _error == nil {
			if _configuration.Debug {
				log.Printf ("[ii] [04157e71]  output file succeeded renaming previous `%s`;\n", _context.currentArchivedPath)
			}
		} else {
			log.Printf ("[ee] [7ad610e7]  output file failed renaming previous `%s` (rename);  ignoring!\n", _context.currentArchivedPath)
			logError (_error, "")
		}
	}
	
	if _configuration.ArchivedCompressSuffix != "" {
		if _error := outputFileCompress (_context, _wait); _error != nil {
			log.Printf ("[ee] [9e80c303]  output file failed compressing previous `%s` (rename);  ignoring!\n", _context.currentArchivedPath)
			logError (_error, "")
		}
	} else {
		log.Printf ("[ii] [c59ca93f]  output file succeeded archiving previous `%s`;\n", _context.currentArchivedPath)
	}
	
	_context.currentFile = nil
	
	return nil
}




func outputFileCompress (_context *OutputFileContext, _wait bool) (error) {
	
	if ! _context.initialized {
		return fmt.Errorf ("[f02c854b]  output file is not initialized!")
	}
	
	_configuration := _context.configuration
	
	_uncompressedPath := _context.currentArchivedPath
	_compressedPathFinal := _uncompressedPath + _configuration.ArchivedCompressSuffix
	_compressedPathTemp := _uncompressedPath + _configuration.ArchivedCompressSuffix + ".tmp"
	
	if _configuration.Debug {
		log.Printf ("[ii] [2d5bbfb2]  output file compressing previous `%s`...\n", _compressedPathFinal)
	}
	
	var _uncompressedFile *os.File
	var _compressedFile *os.File
	var _process *os.Process
	_exitGroup := _context.exitGroup
	
	_exitGroup.Add (1)
	
	_abort := func () (error) {
		os.Remove (_compressedPathFinal)
		os.Remove (_compressedPathTemp)
		if _uncompressedFile != nil {
			_uncompressedFile.Close ()
		}
		if _compressedFile != nil {
			_compressedFile.Close ()
		}
		if _process != nil {
			_process.Kill ()
			_process.Wait ()
		}
		_exitGroup.Done ()
		return fmt.Errorf ("[c3a4f5db]  failed compressing file!")
	}
	
	if _file, _error := os.OpenFile (_uncompressedPath, os.O_RDONLY, _configuration.FileMode); _error == nil {
		_uncompressedFile = _file
	} else {
		logError (_error, "[6a38d1df]  output file failed opening previous uncompressed!")
		return _abort ()
	}
	
	if _file, _error := os.OpenFile (_compressedPathTemp, os.O_CREATE | os.O_EXCL | os.O_WRONLY | os.O_APPEND, _configuration.FileMode); _error == nil {
		_compressedFile = _file
	} else {
		logError (_error, "[36b2959a]  output file failed creating previous compressed!")
		return _abort ()
	}
	
	if _configuration.Debug {
		log.Printf ("[ii] [45c0de44]  output file compress process starting: `%q`...\n", _configuration.ArchivedCompressCommand)
	}
	
	_command := exec.Command (_configuration.ArchivedCompressCommand[0], _configuration.ArchivedCompressCommand[1:] ...)
	_command.Stdin = _uncompressedFile
	_command.Stdout = _compressedFile
	_command.Stderr = os.Stderr
	if _error := _command.Start (); _error == nil {
		_process = _command.Process
	} else {
		logError (_error, "[d591be92]  output file failed executing compress process (exec)!")
		return _abort ()
	}
	
	_uncompressedFile.Close ()
	_uncompressedFile = nil
	_compressedFile.Close ()
	_compressedFile = nil
	
	_finalize := func () (error) {
		
		if _state, _error := _process.Wait (); _error == nil {
			if ! _state.Success () {
				log.Printf ("[ee] [09463fb9]  output file failed executing compress process (exit):  `%s`!\n", _state.Sys ())
				_process = nil
				return _abort ()
			}
		} else {
			logError (_error, "[30dd81af]  output file failed executing compress process (wait)!")
			_process = nil
			return _abort ()
		}
		
		if _error := os.Rename (_compressedPathTemp, _compressedPathFinal); _error != nil {
			logError (_error, "[dd8ff061]  output file failed renaming previous compressed!")
			return _abort ()
		}
		if _error := os.Remove (_uncompressedPath); _error != nil {
			logError (_error, "[9391f70d]  output file failed deleting previous uncompressed!")
			return _abort ()
		}
		
		if _configuration.Debug {
			log.Printf ("[ii] [9b4015d2]  output file succeeded compressing previous `%s`;\n", _compressedPathFinal)
		}
		
		log.Printf ("[ii] [07a39e08]  output file succeeded archiving previous `%s`;\n", _compressedPathFinal)
		
		_exitGroup.Done ()
		
		return nil
	}
	
	if _wait {
		return _finalize ()
	} else {
		go _finalize ()
		return nil
	}
}




func outputStreamProcess (_stream *os.File, _message *Message, _pretty bool, _sequence bool, _flush bool) (error) {
	
	_buffer := make ([]byte, 0, DefaultOutputBufferSize)
	
	if _sequence {
		_buffer = append (_buffer, []byte ("\x1e") ...)
	} else {
		_buffer = append (_buffer, []byte ("\n\n") ...)
	}
	
	{
		var _data []byte
		var _error error
		if _pretty {
			_data, _error = json.MarshalIndent (_message, "", "\t")
		} else {
			_data, _error = json.Marshal (_message)
		}
		if _error != nil {
			return _error
		}
		_buffer = append (_buffer, _data ...)
	}
	
	if _sequence {
		_buffer = append (_buffer, []byte ("\x0a") ...)
	} else {
		_buffer = append (_buffer, []byte ("\n\n") ...)
	}
	
	if _size, _error := _stream.Write (_buffer); _error != nil {
		return _error
	} else if _size != len (_buffer) {
		return fmt.Errorf ("[82772647]  buffer written partially:  `%d` of `%d`!", _size, len (_buffer))
	}
	
	if _flush {
		if _error := _stream.Sync (); _error != nil {
			return _error
		}
	}
	
	return nil
}


