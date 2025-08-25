package vservice_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"
)

func minVSI(t *testing.T, hopcount uint, alog logr.Logger) *vservice.VSIConfig {
	// Minimal config:
	authcert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)
	return &vservice.VSIConfig{
		Log:                   alog,
		CN:                    vservice.VisaServiceCN,
		VSAddr:                netip.MustParseAddr(vservice.VisaServiceAddress),
		HopCount:              hopcount,
		AllowInvalidPeerAddr:  true,
		BootstrapAuthDuration: 1 * time.Hour,
		AuthorityCert:         authcert,
	}
}

// Helper to createa a TCP SYN packet.
func createPacket(pktbuf gopacket.SerializeBuffer, src, dst netip.Addr, srcPort, dstPort uint16) {
	// pktbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	payload := gopacket.Payload([]byte{1, 2, 3, 4})
	payload.SerializeTo(pktbuf, opts)

	tcph := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcph.SerializeTo(pktbuf, opts)

	iph := &layers.IPv6{
		Version:    6,
		SrcIP:      net.IP(src.AsSlice()),
		DstIP:      net.IP(dst.AsSlice()),
		NextHeader: layers.IPProtocolTCP,
	}
	iph.SerializeTo(pktbuf, opts)
}

func helloAndGenNodeAuthReq(t *testing.T, svc *vservice.VSInst, nodeAddr netip.Addr) *vsapi.NodeAuthRequest {
	authKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	authsvc := auth.NewAuthenticator(logr.NewTestLogger(),
		nodeAddr,
		1000*time.Hour,
		"vs.zpr",
		authKey)
	svc.SetAuthSvc(authsvc)

	{
		pfile := filepath.Join("testdata", "vsinst-test.bin")
		cp, err := policy.OpenContainedPolicyFile(pfile, nil)
		require.Nil(t, err)
		polplcy := cp.Policy
		plcy := policy.NewPolicyFromPol(polplcy, logr.NewTestLogger())
		svc.InstallPolicy(1234, 0, plcy)
	}

	hresp, err := svc.Hello(context.Background())
	require.Nil(t, err)

	timestamp := time.Now().Unix()
	sig := createMilestone2HMAC(hresp.Challenge.ChallengeData, hresp.SessionID, timestamp)
	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     nodeAddr.AsSlice(),
		TetherAddr:  nodeAddr.AsSlice(),
		Ident:       uuid.New().String(),
	}
	return &vsapi.NodeAuthRequest{
		SessionID: hresp.SessionID,
		Challenge: hresp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}
}

func TestRequestVisa(t *testing.T) {
	alog := logr.NewTestLogger()

	vc := minVSI(t, 99, alog)

	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)

	naddr := netip.MustParseAddr("fd5a:5052:90de::1")
	nodeAuthReq := helloAndGenNodeAuthReq(t, svc, naddr)

	// Authenticate performs async ops so service needs to be running.
	go svc.Start(netip.MustParseAddr("127.0.0.1"), 0)
	defer svc.Stop()
	time.Sleep(200 * time.Millisecond)

	apiKey, err := svc.Authenticate(context.Background(), nodeAuthReq)
	require.Nil(t, err)

	saddr := netip.MustParseAddr("fd5a:5052:33::1")
	pktbuf := gopacket.NewSerializeBuffer()
	createPacket(pktbuf, saddr, naddr, 30000, 80)

	// Prior to requesting a visa, we need to have told visa service about the
	// adapter(s).
	{
		claims := map[string]*actor.ClaimV{
			actor.KAttrCN: &actor.ClaimV{V: "fee.zpr", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(saddr, saddr, naddr, claims, time.Now().Add(5*time.Minute))
	}

	res, err := svc.RequestVisa(context.Background(), apiKey, saddr.AsSlice(), 6, pktbuf.Bytes())
	require.Nil(t, err)
	require.Equal(t, "", res.GetReason())
	require.Equal(t, vsapi.StatusCode_SUCCESS, res.Status)

	require.NotNil(t, res.GetVisa().Visa)
	err = svc.DeRegister(context.Background(), apiKey)
	time.Sleep(100 * time.Millisecond)
	require.Nil(t, err)
}

func TestRequestVisaDupes(t *testing.T) {
	alog := logr.NewTestLogger()

	// Minimal config:
	vc := minVSI(t, 99, alog)

	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	naddr := netip.MustParseAddr("fd5a:5052:90de::1")

	nodeAuthReq := helloAndGenNodeAuthReq(t, svc, naddr)

	go svc.Start(netip.MustParseAddr("127.0.0.1"), 0)
	defer svc.Stop()
	time.Sleep(200 * time.Millisecond)

	apiKey, err := svc.Authenticate(context.Background(), nodeAuthReq)
	require.Nil(t, err)

	saddr := netip.MustParseAddr("fd5a:5052:33::1")
	pktbuf := gopacket.NewSerializeBuffer()
	createPacket(pktbuf, saddr, naddr, 30000, 80)

	{
		claims := map[string]*actor.ClaimV{
			actor.KAttrCN: &actor.ClaimV{V: "fee.zpr", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(saddr, saddr, naddr, claims, time.Now().Add(5*time.Minute))
	}

	var resp1, resp2 *vsapi.VisaResponse

	{
		resp1, err = svc.RequestVisa(context.Background(), apiKey, saddr.AsSlice(), 6, pktbuf.Bytes())
		require.Nil(t, err)
		require.Equal(t, vsapi.StatusCode_SUCCESS, resp1.Status)
	}
	require.NotNil(t, resp1.GetVisa().Visa)

	// Now request again. For now the visa service will happily create another
	// visa. Possibly we want to prevent this, but one tricky issue is that the
	// visa service must allow new visas to be created that extend the lifetime
	// but are otherwise the same.
	{
		resp2, err = svc.RequestVisa(context.Background(), apiKey, saddr.AsSlice(), 6, pktbuf.Bytes())
		require.Nil(t, err)
		require.Equal(t, vsapi.StatusCode_SUCCESS, resp2.Status)
	}
	require.NotNil(t, resp2.GetVisa().Visa)

	v1 := resp1.Visa.Visa
	require.Nil(t, err)
	v2 := resp2.Visa.Visa
	require.Nil(t, err)

	require.NotEqual(t, v1.IssuerID, v2.IssuerID) // New unique issuer IDs
}

// Ensure that if actor auth has expired, no visa is issued.
func TestAuthExpireNoVisa(t *testing.T) {
	alog := logr.NewTestLogger()

	// Minimal config:
	vc := minVSI(t, 99, alog)

	// TODO: This initializer is insane. Too hard to test, need to refactor.
	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	naddr := netip.MustParseAddr("fd5a:5052:90de::1")

	nodeAuthReq := helloAndGenNodeAuthReq(t, svc, naddr)

	go svc.Start(netip.MustParseAddr("127.0.0.1"), 0)
	defer svc.Stop()
	time.Sleep(200 * time.Millisecond)

	apiKey, err := svc.Authenticate(context.Background(), nodeAuthReq)
	require.Nil(t, err)

	saddr := netip.MustParseAddr("fd5a:5052:33::1")
	pktbuf := gopacket.NewSerializeBuffer()
	createPacket(pktbuf, saddr, naddr, 30000, 80)

	{
		claims := map[string]*actor.ClaimV{
			actor.KAttrCN: &actor.ClaimV{V: "fee.zpr", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(saddr, saddr, naddr, claims, time.Now().Add(-time.Hour)) // <--- note expired
	}

	res, err := svc.RequestVisa(context.Background(), apiKey, saddr.AsSlice(), 6, pktbuf.Bytes())
	require.Nil(t, err)
	require.Equal(t, vsapi.StatusCode_FAIL, res.Status)
	require.Equal(t, "auth expired", res.GetReason())
}
