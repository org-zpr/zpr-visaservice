package auth

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"sync"

	"zpr.org/polio"
	"zpr.org/vsapi"
)

type ActorAuthDB struct {
	sync.RWMutex

	version uint64
	db      map[string]*vsapi.ServiceDescriptor
}

func NewActorAuthDB() *ActorAuthDB {
	return &ActorAuthDB{
		version: 1, // Do not use 0.
		db:      make(map[string]*vsapi.ServiceDescriptor),
	}
}

// Get the current database version. Adds and removes increment the version.
// Version is always >= 1.
func (adb *ActorAuthDB) Version() uint64 {
	adb.RLock()
	defer adb.RUnlock()
	return adb.version
}

// Get a copy of the actor authentication service database.
func (adb *ActorAuthDB) ListServices() []*vsapi.ServiceDescriptor {
	adb.RLock()
	defer adb.RUnlock()
	services := make([]*vsapi.ServiceDescriptor, 0, len(adb.db))
	for _, svc := range adb.db {
		scopy := vsapi.ServiceDescriptor{
			Type:      svc.Type,
			ServiceID: svc.ServiceID,
			URI:       svc.URI,
			Address:   make([]byte, len(svc.Address)),
		}
		copy(scopy.Address, svc.Address)
		services = append(services, &scopy)
	}
	return services
}

// Add a new actor authentication service to the database. If there is a database change
// the version is incremented.
//
// `zprAddr` - is the address granted to the adapter fronting the service.
func (adb *ActorAuthDB) AddActorAuthService(psvc *polio.Service, zprAddr netip.Addr) (uint64, error) {

	adb.Lock()
	defer adb.Unlock()

	serviceName := psvc.GetName()
	if psvc == nil {
		return adb.version, fmt.Errorf("service not found in policy: %v", serviceName)
	}
	if psvc.Type != polio.SvcT_SVCT_ACTOR_AUTH {
		return adb.version, fmt.Errorf("not an actor auth service: %v", serviceName)
	}

	urlp, err := url.Parse(psvc.ValidateUri)
	if err != nil {
		return adb.version, fmt.Errorf("policy error: invalid validate-uri: %v: %w", psvc.ValidateUri, err)
	}
	if urlp.Scheme != "zpr-oauthrsa" {
		// TODO: In future there will be several schemes.
		return adb.version, fmt.Errorf("policy error: invalid validate scheme: %v", psvc.ValidateUri)
	}
	portStr := urlp.Port() // get port from policy
	if portStr == "" {
		portStr = fmt.Sprintf("%d", ZPR_OAUTH_RSA_PORT_DEFAULT) // default for THIS scheme
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return adb.version, fmt.Errorf("invalid port in validate-uri: '%s'", portStr)
	}

	// We leave the Scheme alone in the URL as it comes from policy.  The client
	// adapter will use the scheme to determine how to connect to the service.
	// In this case it is "zpr-oauthrsa" which means "open an HTTPS connection
	// to <ADDR>:<PORT>/preauthorize".

	// TODO: To support TLS we should be able to put a hostname into the URI.
	urlp.Host = fmt.Sprintf("[%s]:%d", zprAddr.String(), portNum) // Note IPv6
	fixedValidateUri := urlp.String()

	svcd := vsapi.ServiceDescriptor{
		Type:      vsapi.ServiceType_ACTOR_AUTHENTICATION,
		ServiceID: serviceName,
		URI:       fixedValidateUri,
		Address:   zprAddr.AsSlice(),
	}
	if entry, exists := adb.db[serviceName]; exists {
		if isSameService(entry, &svcd) {
			return adb.version, nil // no change
		}
	}
	adb.db[serviceName] = &svcd
	adb.version++
	return adb.version, nil
}

// Remove an actor authentication service from the database. If there is a database change
// the version is incremented. If the service does not exist, the version
// is returned unchanged.
func (adb *ActorAuthDB) RemoveActorAuthService(serviceName string) uint64 {
	adb.Lock()
	defer adb.Unlock()
	if _, exists := adb.db[serviceName]; !exists {
		return adb.version
	}
	delete(adb.db, serviceName)
	adb.version++
	return adb.version
}

func isSameService(a, b *vsapi.ServiceDescriptor) bool {
	if a.Type != b.Type || a.ServiceID != b.ServiceID {
		return false
	}
	if a.URI != b.URI {
		return false
	}
	if len(a.Address) != len(b.Address) {
		return false
	}
	for i := range a.Address {
		if a.Address[i] != b.Address[i] {
			return false
		}
	}
	return true
}
