package actor

// Well known actor attribute keys in ZPR namespace
const (
	KAttrEPID               = "zpr.addr"                 // ZPR contact address (was Endpoint ID) required for nodes and services
	KAttrAuthority          = "zpr.authority"            // authority identifier
	KAttrConnectVia         = "zpr.connect_via"          // connect-via
	KAttrRole               = "zpr.role"                 // role, eg "node"
	KAttrVisaServiceAdapter = "zpr.visa_service_adapter" // true or false
	KAttrHash               = "zpr.hash"
	KAttrConfigID           = "zpr.config_id"
	KAttrCN                 = "endpoint.zpr.adapter.cn"
	KAttrAAANet             = "endpoint.zpr.node.aaa_net"
	KAttrServices           = "zpr.services" // comma-separated list of service names provided.
)

const (
	KAttrActorAuthority = "authority" // Actor requested authority
)

type Namespace int

const (
	NsUser Namespace = iota + 1
	NsEndpoint
	NsService
)

func (n Namespace) String() string {
	switch n {
	case NsUser:
		return "user"
	case NsEndpoint:
		return "endpoint"
	case NsService:
		return "service"
	default:
		return "unknown"
	}
}

func ParseNamespace(s string) (Namespace, bool) {
	switch s {
	case "user":
		return NsUser, true
	case "endpoint":
		return NsEndpoint, true
	case "service":
		return NsService, true
	default:
		return 0, false
	}
}
