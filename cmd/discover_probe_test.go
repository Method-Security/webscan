package cmd

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDiscoverWebServer(t *testing.T) {
	ipAddress, port, protocol, err := parseDiscoverWebServer("18.170.80.13,443,https")

	require.NoError(t, err)
	assert.Equal(t, "18.170.80.13", ipAddress)
	assert.Equal(t, 443, port)
	assert.Equal(t, common.WebProtocolHttps, protocol)
}

func TestValidateDiscoverWebServersRejectsMalformedValues(t *testing.T) {
	err := validateDiscoverWebServers([]string{"18.170.80.12,HTTP"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ip,port,protocol")
}
