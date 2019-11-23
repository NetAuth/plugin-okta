package main

import (
	"github.com/netauth/plugin-okta/impl"

	"github.com/netauth/netauth/pkg/plugin/tree"
)

func main() {
	tree.PluginMain(impl.New())
}
