package policy

import (
	"fmt"
)

// VS is compatible with this version of the policy compiler.
const (
	CompilerMajorVersion    = uint32(0)
	CompilerMinorVersion    = uint32(4)
	CompilerPatchVersionMin = uint32(1)
)

const (
	ConfKeyCIDR      = "cidr"
	NoProc           = uint32(0xFFFFFFFF)
	NoHash           = uint32(0xFFFFFFFF)
	AuthProtocol     = 0x6   // TCP (gRPC protocol to auth services)
	AuthProtocolName = "TCP" // TCP (gRPC protocol to auth services)
	VisaServiceName  = "$$zpr/visaservice"
)

// As things are rapidly changing the visa service is fairly rigid about
// what versions of the compiler output it will accept.  Major and minor
// versions must match exactly.
func IsCompatibleVersion(major, minor, patch uint32) bool {
	return major == CompilerMajorVersion && minor == CompilerMinorVersion && patch >= CompilerPatchVersionMin
}

// Pass a version string of the form "x.y.z" to check compatibility.
func IsCompatibleVersionStr(version string) bool {
	var major, minor, patch uint32
	if _, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	return IsCompatibleVersion(major, minor, patch)
}
