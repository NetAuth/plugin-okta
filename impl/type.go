package impl

import (
	"github.com/okta/okta-sdk-golang/okta"

	"github.com/netauth/netauth/pkg/plugin/tree"
)

// OktaPlugin is the implementation of the plugin that can talk to
// both netauth and to Okta.
type OktaPlugin struct {
	tree.NullPlugin

	c *okta.Client
}
