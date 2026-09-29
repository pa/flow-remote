// Package web holds the phone app, embedded so `flow-remote serve` serves
// it without a separate folder. Test files are left out by listing what
// ships.
package web

import "embed"

//go:embed index.html app.css sw.js manifest.webmanifest icon.svg icon-180.png icon-192.png icon-512.png flow-wave.svg js/*.js vendor
var Files embed.FS
