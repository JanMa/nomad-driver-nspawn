package main

import (
	log "github.com/hashicorp/go-hclog"

	"github.com/JanMa/nomad-driver-nspawn/nspawn"
	"github.com/hashicorp/nomad/plugins"
)

func main() {
	// Serve the plugin
	plugins.Serve(factory)
}

// factory returns a new instance of the nspawn driver plugin
func factory(log log.Logger) interface{} {
	return nspawn.NewNspawnDriver(log)
}
