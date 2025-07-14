package policy_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/polio"
	"zpr.org/vs/pkg/policy"
)

func TestSignVerifyPolicy(t *testing.T) {

	plcy := &polio.Policy{
		PolicyVersion:  33,
		PolicyMetadata: "fee fie foh fum",
	}

	private, err := rsa.GenerateKey(rand.Reader, 768)
	require.Nil(t, err)

	pcont, err := policy.ContainPolicy(plcy, private)
	require.Nil(t, err)
	require.NotNil(t, pcont)

	require.Equal(t, pcont.VersionMajor, policy.CompilerMajorVersion)
	require.Equal(t, pcont.VersionMinor, policy.CompilerMinorVersion)
	require.Equal(t, pcont.VersionPatch, policy.CompilerPatchVersionMin)

	require.NotNil(t, pcont.GetSignature())
	require.Equal(t, uint64(33), pcont.GetPolicyVersion())

	pp, err := policy.ReleasePolicy(pcont, &private.PublicKey)
	require.Nil(t, err)
	require.Equal(t, plcy.GetPolicyMetadata(), pp.GetPolicyMetadata())
}
