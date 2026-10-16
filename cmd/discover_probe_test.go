package cmd

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDiscoverProbeWebServers(t *testing.T) {
	webServers, err := parseDiscoverProbeWebServers([]string{
		"18.170.80.12,80,HTTP",
		"18.170.80.13,443,https",
	})

	require.NoError(t, err)
	require.Len(t, webServers, 2)
	assert.Equal(t, "18.170.80.12", webServers[0].IpAddress)
	assert.Equal(t, 80, webServers[0].Port)
	assert.Equal(t, common.WebProtocolHttp, webServers[0].ApplicationProtocol)
	assert.Equal(t, "18.170.80.13", webServers[1].IpAddress)
	assert.Equal(t, 443, webServers[1].Port)
	assert.Equal(t, common.WebProtocolHttps, webServers[1].ApplicationProtocol)
}

func TestParseDiscoverProbeWebServersRejectsMalformedValues(t *testing.T) {
	_, err := parseDiscoverProbeWebServers([]string{"18.170.80.12,HTTP"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ip,port,protocol")
}
