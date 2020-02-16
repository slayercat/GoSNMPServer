package GoSNMPServer

import "testing"
import "github.com/stretchr/testify/assert"

func TestHelper_oidToByteString(t *testing.T) {
	oidToByteString("1.2.3.4.5")
}

func TestHelper_IsValidObjectIdentifier(t *testing.T) {
	assert.True(t, IsValidObjectIdentifier("1.2.3.4.5"))
	assert.True(t, IsValidObjectIdentifier(".1.2.3.4.5"))
	assert.False(t, IsValidObjectIdentifier(""))
	assert.False(t, IsValidObjectIdentifier("asdfdasf"))
	assert.False(t, IsValidObjectIdentifier("1..2.3.4.5"))
}
