package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetAddr(t *testing.T) {
	c := ServerConfig{
		Host: "",
		Port: 3000,
	}
	assert.Equal(t, ":3000", c.GetAddr())

	c = ServerConfig{
		Host: "0.0.0.0",
		Port: 3000,
	}
	assert.Equal(t, "0.0.0.0:3000", c.GetAddr())
}
