package client

import (
	"crypto/tls"
	"net/http"
)

func (c *ClientConfig) NewClient() *http.Client {
	// Create a CA certificate pool and add cert.pem to it
	client := &http.Client{}
	if c.tlsConf != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: c.tlsConf,
		}
	}
	return client
}

func (c *ClientConfig) GetTlsConfig() *tls.Config {
	return c.tlsConf
}
