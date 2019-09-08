package main

import (
	"github.com/NetAuth/plugin-okta/impl"

	"github.com/NetAuth/NetAuth/pkg/plugin/tree"
)

func main() {
	tree.PluginMain(impl.New())
}
