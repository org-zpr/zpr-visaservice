package auth_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vservice/auth"
)

/* TODO: Need to update and recompile the test data

const BAS_CN = "bas.zpr.org"

func TestAuthenticateWithSelfSignedBlob(t *testing.T) {

	authKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	authsvc := auth.NewAuthenticator(logr.NewTestLogger(),
		netip.MustParseAddr("127.0.0.1"),
		1000*time.Hour,
		"vs.zpr",
		authKey)

	pfile := filepath.Join("testdata", "vs-auth-test.bin")
	cp, err := policy.OpenContainedPolicyFile(pfile, nil)
	require.Nil(t, err)
	polplcy := cp.Policy
	plcy := policy.NewPolicyFromPol(polplcy, logr.NewTestLogger())
	authsvc.InstallPolicy(1234, 0, plcy)

	pkey, err := snauth.LoadRSAKeyFromFile(filepath.Join("testdata", "bas.zpr.org_key.pem"))
	require.Nil(t, err)

	blob := auth.NewZdpSelfSignedBlobUnsiged(BAS_CN, []byte("fake-challenge-bytes-are-here"))
	err = blob.Sign(pkey)
	require.Nil(t, err)

	addr := netip.MustParseAddr("fd5a:5052::33")
	claims := make(map[string]string)
	claims[actor.KAttrCN] = BAS_CN
	aok, err := authsvc.Authenticate(auth.AUTH_PREFIX_BOOTSTRAP, addr, blob, claims)
	require.Nil(t, err)
	require.NotNil(t, aok)

	require.NotEmpty(t, aok.Identities)
	require.True(t, aok.Expire.After(time.Now()))
	require.Len(t, aok.Prefixes, 1)
	require.Equal(t, aok.Prefixes[0], auth.AUTH_PREFIX_BOOTSTRAP)
	require.NotEmpty(t, aok.Credentials)

	var keys []string
	for k := range aok.Claims {
		keys = append(keys, k)
	}
	require.Contains(t, keys, actor.KAttrCN)
	require.Contains(t, keys, actor.KAttrAuthority)
	require.Contains(t, keys, actor.KAttrConfigID)
	require.Contains(t, keys, actor.KAttrEPID)
}

*/

func TestKeyAndNsForAttrSpec(t *testing.T) {

	auth := auth.NewAuthenticator(logr.NewTestLogger(),
		netip.MustParseAddr("127.0.0.1"),
		1000*time.Hour,
		"vs.zpr",
		nil)

	// Test basic user namespace
	zpl_attr, ns, ok := auth.KeyAndNsForAttrSpec("user.email")
	require.True(t, ok)
	require.Equal(t, "email", zpl_attr)
	require.Equal(t, actor.NsUser, ns)

	// Test endpoint namespace
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("endpoint.hostname")
	require.True(t, ok)
	require.Equal(t, "hostname", zpl_attr)
	require.Equal(t, actor.NsEndpoint, ns)

	// Test service namespace
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("service.port")
	require.True(t, ok)
	require.Equal(t, "port", zpl_attr)
	require.Equal(t, actor.NsService, ns)

	// Test with tag marker (#)
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("#user.role")
	require.True(t, ok)
	require.Equal(t, "role", zpl_attr)
	require.Equal(t, actor.NsUser, ns)

	// Test with multi marker ({})
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("user.groups{}")
	require.True(t, ok)
	require.Equal(t, "groups", zpl_attr)
	require.Equal(t, actor.NsUser, ns)

	// Test with all markers combined
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("#endpoint.interfaces{}")
	require.True(t, ok)
	require.Equal(t, "interfaces", zpl_attr)
	require.Equal(t, actor.NsEndpoint, ns)

	// Test complex attribute names
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("user.full_name")
	require.True(t, ok)
	require.Equal(t, "full_name", zpl_attr)
	require.Equal(t, actor.NsUser, ns)

	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("service.api-version")
	require.True(t, ok)
	require.Equal(t, "api-version", zpl_attr)
	require.Equal(t, actor.NsService, ns)

	// Test invalid cases - no dot separator
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("useremail")
	require.False(t, ok)
	require.Equal(t, "", zpl_attr)
	require.Equal(t, actor.Namespace(0), ns)

	// Test invalid namespace
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("invalid.attr")
	require.False(t, ok)
	require.Equal(t, "", zpl_attr)
	require.Equal(t, actor.Namespace(0), ns)

	// Test empty string
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("")
	require.False(t, ok)
	require.Equal(t, "", zpl_attr)
	require.Equal(t, actor.Namespace(0), ns)

	// Test only namespace without attribute
	zpl_attr, ns, ok = auth.KeyAndNsForAttrSpec("user.")
	require.True(t, ok)
	require.Equal(t, "", zpl_attr)
	require.Equal(t, actor.NsUser, ns)

}
