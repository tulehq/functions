package app

import (
	// The SQLite driver gas/database opens the store with, registered as
	// "sqlite". It is pure Go, so the binary needs no cgo.
	_ "modernc.org/sqlite"
)
