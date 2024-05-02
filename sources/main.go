

package main


import "log"
import "os"
import "regexp"




func main () () {
	
	log.SetFlags (0)
	
	if _error := bootstrap (); _error == nil {
		os.Exit (0)
	} else {
		logError (_error, "")
		log.Printf ("[!!] [01ede391]  aborting!\n")
		os.Exit (1)
	}
}




func logError (_error error, _message string) () {
	
	if _message == "" {
		_message = "[906eea03]  unexpected error encountered!"
	}
	log.Printf ("[ee] %s\n", _message)
	
	_errorString := _error.Error ()
	if _matches, _matchesError := regexp.MatchString (`^\[[0-9a-f]{8}\] [^\n]+$`, _errorString); _matchesError == nil {
		if _matches {
			log.Printf ("[ee] %s\n", _errorString)
		} else {
			log.Printf ("[ee] [8a968eeb]  %q\n", _errorString)
			log.Printf ("[ee] [72c99d89]  %#v\n", _error)
		}
	} else {
		panic (_matchesError)
	}
}


