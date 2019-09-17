# Okta

[![Go Report Card](https://goreportcard.com/badge/github.com/NetAuth/plugin-okta)](https://goreportcard.com/report/github.com/NetAuth/plugin-okta)

The Okta plugin provides a means to synchronize your NetAuth server
with Okta.  This allows you to easily use Okta to provide SAML and
OIDC services with the same credentials that the rest of your
environment uses.

Install it like all plugins by placing it in your server's plugin
directory, and add a configuration stanza to your server configuration
file as follows:

```
[plugin.okta]
  token = "<api_token>"
  domain = "<domain>"
  orgurl = "<sign_on_url>"
  interval = "<sync_interval>"
```

The API token can be obtained from the Okta interface in the bottom of
the Security drop down.  Your sign on URL is the URL you sign on to
Okta including the `http` prefix.  The domain is the URL that entities
will be concatentated to when creating Okta accounts.  The Okta
accounts will be of the format `<ID>@<domain>`.  Finally the interval
is how frequently to synchronize the information to Okta.
