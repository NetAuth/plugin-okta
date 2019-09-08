package impl

import (
	"github.com/okta/okta-sdk-golang/okta"

	"github.com/NetAuth/NetAuth/pkg/plugin/tree"
)

// OktaPlugin is the implementation of the plugin that can talk to
// both NetAuth and to Okta.
type OktaPlugin struct {
	tree.NullPlugin

	c *okta.Client
}
