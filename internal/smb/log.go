package smb

import "log"

// debugEnabled turns on per-request debug logging (the -v flag).
var debugEnabled = false

// SetDebug enables or disables per-request debug logging.
func SetDebug(on bool) {
	debugEnabled = on
}

func debugf(format string, args ...any) {
	if debugEnabled {
		log.Printf("DEBUG: "+format, args...)
	}
}

func logf(format string, args ...any) {
	log.Printf(format, args...)
}

func errorf(format string, args ...any) {
	log.Printf("ERROR: "+format, args...)
}
