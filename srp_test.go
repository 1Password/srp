package srp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// These tests are based on SRP Test Vectors
// https://tools.ietf.org/html/rfc5054#appendix-B

var expectedX = NumberFromString("0x 94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")

var expectedVerifier = hexNumberString(
	"7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812" +
		"9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5" +
		"C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5" +
		"EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78" +
		"E955A5E2 9E7AB245 DB2BE315 E2099AFB")

//nolint:exhaustruct
var g1024 = &Group{g: big.NewInt(2), n: NumberFromString("0x EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
	"9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
	"8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
	"7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
	"FD5138FE8376435B9FC61D2FC0EB06E3"), Label: "5054A1024"}

func init() {
	KnownGroups[RFC5054Group1024] = g1024
}

func hexNumberString(s string) *big.Int {
	result, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	n := &big.Int{}
	return n.SetBytes(result)
}

// Auth contains information on the type of auth used.
type Auth struct {
	Method     string `json:"method"`
	Alg        string `json:"alg"`
	Iterations uint32 `json:"iterations"`
	Salt       string `json:"salt"`
}

func TestCalculateClientRawKey(t *testing.T) {
	x := NumberFromString("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773")
	a := NumberFromString("f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06")
	//nolint:lll
	B := NumberFromString("780a5495cbf731d2463fd01d28822e7d9ccf697c4239d5151f85666aa06b3767e0301b54cfad3bd2b526d4d8a1d96492e59c8d8ecddca96b7e288f186155ffa57b50df6bc2103b6004400b797334a22d9dd234b40142a5ab714ea6070d2ed55096049f50efba99862b72f7e7aee51ed71ba6663fff570cc713d456316f3535630e87a245f09b0791c6e687baa65bf2dfb5c17e50c250256cdad4c9851a2484e88326888060ae9578b5a60e0c85143b25f4fb4fca794e266a4359642da085672d6a3b881649a387875685aeb1ae3d809bf7818dcad596c6e29d566ae87c0ad645a0fcc2eb4f066c097670adf48cf0954918fda4dc30588261321d592f890eed87a950d387b48cf6b4a49f9d497323f683091ae6a4efe675d6bfc4393c0c3d54c9adad65b8dd3a7b7e85cd5d31e97bebc8f23b370348dab53903ec5085cbf65de5e5491f417e5bf9953f081e788f36c26cbe00664a1256c4befb00765ea7e432af189521442c186f14442b1957e444426f740f363ebda943da2bb3b18a13e2f41be9cc3ca0a1b111f6983f9b8d0ee0f4b573c6042fbc0ca029821ebe517ed0755a94f42d32b0abef9240af0f37b5fe0e90c4ca83acf91d28a7f3acff5657bf69fdb7747e380b23fd437f637da2f7ebcf8733a69a75715fe3894e1799906b48e3ae818332cf5f9533e7af5a1f065f907c8f31fe778fa2da853e69926fc551d6b3ae")
	u := NumberFromString("dad353365f78590c1857b29f16e3a947df4707868e2dd2d2b4eafd35c8c854a1")
	k := NumberFromString("4832374a524b354d344e424a584f42434f45544356584a484641")
	expectedKey, _ := hex.DecodeString("f6bef3d6fa5a08a849bf61041cd5b3185c16aede851c819a3644fa7e918c4da6")

	groupID := RFC5054Group4096
	client := NewSRPClient(KnownGroups[groupID], x, k)
	client.ephemeralPrivate = a
	if _, err := client.makeA(); err != nil {
		t.Error(err)
	}
	if err := client.SetOthersPublic(B); err != nil {
		t.Error(err)
	}
	client.u = u
	key, _ := client.Key()

	if !bytes.Equal(client.key, expectedKey) {
		t.Errorf("key doesn't match expected key.\n%x\n!=\n%x", key, expectedKey)
	}
}

func TestNewSRPClient(t *testing.T) {
	var err error
	x := NumberFromString("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773")
	s := NewSRPClient(KnownGroups[RFC5054Group4096], x, nil)

	expectedV4096 := NumberFromString("d05240ed513a4f267608e64cf2a84f5106741ddbf1435707a84f530207409d7" +
		"af1e671182f9d77855b61c628df2b8f6ba8e9b6068fbc84fab80b4542f44c666e17358ebffa8d6fb00fd7037a" +
		"b9ee450413f240ab1e4b586e48bf43ce38f41ad7e406d0150ea83c8f216db4dec06ec5d9fb1cbfd049f70438f" +
		"c14a2faa2a920ad1b298bb1c70989d17163cf52632f202e77824d71c0ff2dd2ef63ebdcd6140beb471b9a7f7b" +
		"14e2d45478994dac95d27f2b45404e564c90eb65655bf6a789bfd665035f711b7cf766a380b921a666dfcfee0" +
		"238b27eafdd8a953a50cc2c4f291458d48ef9fd0740da59aa325b9165ebb97d125511b03e1056bd448b322d7d" +
		"250816783462cff6f9ecd40813522dac10329b7c4bcd0c8f0ceec2eb2c46ba442ac62a84994e2fcdb94cbfe05" +
		"7cad578c5e4d28822cd283e8430b8a1e1106f6e2536e8596b8a0de46717fbd4e9f06b796364aa930bbcf87433" +
		"cbbbf15b077b2998569027edcae71d09112857d0fac06d9f9f70371f43f8581a229c290ade4e63251f8d8a0c9" +
		"61e20d357069472db3ff422c3ecacf6ff9b2af54003d6aa344a37e7a7f04a1a667d5299475cea6b02c09b5850" +
		"5c895efbd86703a0a375ccdf81616e8bee6cfc947467c4bcbe4a7d3e245df32cd7192e212ffe635ff8ac9727d" +
		"6fe05ede8338f6f3bc18b5359ea8afc13ce3952cd426fb0934c5ea54e71e10bf81028f")

	if s.ephemeralPublicA == nil {
		t.Errorf("A was not calculated")
	}
	if _, err = s.Verifier(); err != nil {
		t.Errorf("couldn't make v: %s", err)
	}

	if expectedV4096.Cmp(s.v) != 0 {
		t.Errorf("v mismatch\n\tExpected:\t%s\n\tReceived:\t%s", expectedV4096, s.v)
	}
}

func TestSRPVerifier1024(t *testing.T) {
	var err error
	var clientV *big.Int
	x := expectedX
	s := NewSRPClient(KnownGroups[RFC5054Group1024], x, nil)

	if clientV, err = s.Verifier(); err != nil {
		t.Errorf("couldn't make v: %s", err)
	}

	if expectedVerifier.Cmp(clientV) != 0 {
		t.Errorf("v mismatch\n\tExpected:\t%s\n\tReceived:\t%s", expectedVerifier, clientV)
	}
}

// TestNewSRPAgainstSpec tests against Appendix B of rfc5054.
// This test does not include the derivation of x, which is in
// TestKDFRFC5054.
func TestNewSRPAgainstSpec(t *testing.T) {
	// Given standard SRP test vectors from http://tools.ietf.org/html/rfc5054#appendix-B
	groupID := RFC5054Group1024

	x := NumberFromString("0x 94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
	v := NumberFromString("0x " +
		"7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812" +
		"9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5" +
		"C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5" +
		"EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78" +
		"E955A5E2 9E7AB245 DB2BE315 E2099AFB")
	k := NumberFromString("0x 7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")

	a := NumberFromString("0x 60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
	A := NumberFromString("0x " +
		"61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4" +
		"4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC" +
		"8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44" +
		"BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA" +
		"B349EF5D 76988A36 72FAC47B 0769447B")

	b := NumberFromString("0x E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")
	B := NumberFromString("0x " +
		"BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011" +
		"BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99" +
		"6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA" +
		"37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE" +
		"EB4012B7 D7665238 A8E3FB00 4B117B58")

	u := NumberFromString("0x CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019")

	premasterSecret := NumberFromString("0x " +
		"B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D" +
		"233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C" +
		"41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F" +
		"3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D" +
		"C346D7E4 74B29EDE 8A469FFE CA686E5A")

	server := NewSRPServer(KnownGroups[groupID], v, k)

	var err error
	var ret *big.Int
	var retBytes []byte

	// Our calculation of k is not compatable with RFC5054
	if server.k.Cmp(k) != 0 {
		t.Error("Didn't set k, it seems")
	}

	// force use of test vector b
	server.ephemeralPrivate = b

	// We will to force remaking of B and u after setting b
	// might as well test those as we do remake them
	if ret, err = server.makeB(); err != nil {
		t.Errorf("MakeB failed: %s", err)
	}
	if ret.Cmp(server.EphemeralPublic()) != 0 {
		t.Error("B does not equal B (nobody tell Ayn Rand)")
	}
	if server.EphemeralPublic().Cmp(B) != 0 {
		t.Error("B is incorrect")
	}

	if err := server.SetOthersPublic(A); err != nil {
		t.Error(err)
	}
	if ret, err = server.calculateU(); err != nil {
		t.Errorf("calculateU failed: %s", err)
	}
	if ret.Cmp(server.u) != 0 {
		t.Error("u does not equal u (nobody tell Ayn Rand)")
	}
	if u.Cmp(server.u) == 0 {
		t.Error("A miracle: u meets 5054 expected value")
	}

	// Force use of test vector u
	server.u = u
	if retBytes, err = server.Key(); err != nil {
		t.Errorf("MakeKey failed: %s", err)
	}
	if !bytes.Equal(retBytes, server.key) {
		t.Error("Key does not equal Key (nobody tell Ayn Rand)")
	}
	if premasterSecret.Cmp(server.premasterKey) != 0 {
		t.Error("premasterKey is incorrect")
	}

	// Now lets compute the key from the client side

	client := NewSRPClient(KnownGroups[groupID], x, k)

	// Force use of test vector a
	client.ephemeralPrivate = a

	// Will need to force remake of A and u after setting a
	if ret, err = client.makeA(); err != nil {
		t.Errorf("MakeA failed: %s", err)
	}
	if ret.Cmp(client.EphemeralPublic()) != 0 {
		t.Error("A does not equal A (nobody tell Ayn Rand)")
	}

	if client.EphemeralPublic().Cmp(A) != 0 {
		t.Error("A is incorrect")
	}

	if err = client.SetOthersPublic(B); err != nil {
		t.Errorf("client couldn't set B: %s", err)
	}
	if ret, err = client.calculateU(); err != nil {
		t.Errorf("calculated client u failed: %s", err)
	}
	if ret.Cmp(client.u) != 0 {
		t.Error("client u does not equal u (nobody tell Ayn Rand)")
	}
	if u.Cmp(client.u) == 0 {
		t.Error("A miracle: client u meets 5054 expected value")
	}
}

func TestClientServerMatch(t *testing.T) {
	var err error
	var v *big.Int
	groupID := RFC5054Group2048

	xbytes := make([]byte, 32)
	if _, err := rand.Read(xbytes); err != nil {
		t.Error(err)
	}
	x := &big.Int{}
	x.SetBytes(xbytes)

	client := NewSRPClient(KnownGroups[groupID], x, nil)

	if v, err = client.Verifier(); err != nil {
		t.Errorf("verifier creation failed: %s", err)
	}

	server := NewSRPServer(KnownGroups[groupID], v, nil)

	A := client.EphemeralPublic()
	B := server.EphemeralPublic()
	if err := server.SetOthersPublic(A); err != nil {
		t.Error(err)
	}
	if err := client.SetOthersPublic(B); err != nil {
		t.Error(err)
	}

	serverKey, _ := server.Key()
	clientKey, _ := client.Key()

	if server.k.Cmp(client.k) != 0 {
		t.Error("Server and Client k don't match")
	}
	if server.u.Cmp(client.u) != 0 {
		t.Error("Server and Client u don't match")
	}
	if !bytes.Equal(serverKey, clientKey) {
		t.Error("Server and Client keys don't match")
	}
}

// Test that "old" behavior with server selected k works.
func TestClientServerMatchK(t *testing.T) {
	var err error
	var v *big.Int
	groupID := RFC5054Group4096

	xbytes := make([]byte, 32)
	if _, err := rand.Read(xbytes); err != nil {
		t.Error(err)
	}
	x := &big.Int{}
	x.SetBytes(xbytes)

	// In 1Password, server selectec k is session IDs, random 16 bytes
	k := NumberFromString("0xa611d95647dcd1ccf38eae713169dbf9")

	client := NewSRPClient(KnownGroups[groupID], x, k)

	if v, err = client.Verifier(); err != nil {
		t.Errorf("verifier creation failed: %s", err)
	}

	server := NewSRPServer(KnownGroups[groupID], v, k)

	A := client.EphemeralPublic()
	B := server.EphemeralPublic()
	if err := server.SetOthersPublic(A); err != nil {
		t.Error(err)
	}
	if err := client.SetOthersPublic(B); err != nil {
		t.Error(err)
	}

	serverKey, _ := server.Key()
	clientKey, _ := client.Key()

	if server.k.Cmp(client.k) != 0 {
		t.Error("Server and Client k don't match")
	}
	if server.k.Cmp(k) != 0 {
		t.Error("Server k was not set manually")
	}
	if server.u.Cmp(client.u) != 0 {
		t.Error("Server and Client u don't match")
	}
	if !bytes.Equal(serverKey, clientKey) {
		t.Error("Server and Client keys don't match")
	}
}

// TestBadA checks that if A mod N = 0 errors are returned and no key created.
func TestBadA(t *testing.T) {
	xbytes := make([]byte, 32)
	if _, err := rand.Read(xbytes); err != nil {
		t.Error(err)
	}
	v := &big.Int{}
	v.SetBytes(xbytes)
	grp := KnownGroups[RFC5054Group2048]
	N := grp.N()

	server := NewSRPServer(grp, v, nil)
	if server == nil {
		t.Error("failed to create server")
	}
	multiples := []int{0, 1, -3, 5}
	for m := range multiples {
		A := (&big.Int{}).Mul(big.NewInt(int64(m)), N)

		if err := server.SetOthersPublic(A); err == nil {
			t.Error("a bad A was accepted")
		}

		key, err := server.Key()
		if err == nil {
			t.Error("no error on key creation after bad A")
		}
		if key != nil {
			t.Error("key created after bad A")
		}
	}
}

// TestBadB checks that if A mod N = 1 errors are returned and no key created.
func TestBadB(t *testing.T) {
	xbytes := make([]byte, 32)
	if _, err := rand.Read(xbytes); err != nil {
		t.Error(err)
	}
	x := &big.Int{}
	x.SetBytes(xbytes)
	grp := KnownGroups[RFC5054Group2048]
	N := grp.N()

	client := NewSRPClient(grp, x, nil)
	if client == nil {
		t.Error("failed to create client")
	}
	multiples := []int{0, 1, -3, 5}
	for m := range multiples {
		B := (&big.Int{}).Mul(big.NewInt(int64(m)), N)
		B = B.Add(bigOne, B)

		if err := client.SetOthersPublic(B); err == nil {
			t.Error("a bad B was accepted")
		}

		key, err := client.Key()
		if err == nil {
			t.Error("no error on key creation after bad B")
		}
		if key != nil {
			t.Error("key created after bad B")
		}
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(38, 32) != 38 {
		t.Error("maxInt is wrong")
	}

	if maxInt(32, 38) != 38 {
		t.Error("maxInt is wrong")
	}

	if maxInt(38) != 38 {
		t.Error("maxInt is wrong")
	}

	if maxInt(0, 40, 32, 32, 40) != 40 {
		t.Error("maxInt is wrong")
	}

	if maxInt(-38, -32) != -32 {
		t.Error("maxInt is wrong")
	}
}

func TestCalculateU(t *testing.T) {
	v := big.NewInt(42)   // value doesn't matter for this test
	k := big.NewInt(2038) // End of the world. Value doesn't matter

	// These are designed to test various combinations of the removing leading "0"s
	testStrings := []string{
		"0123456789ab", // these fail (probably my expectations are wrong)
		"123456789abd",
		"0fff12341234",
		"ffff12341234",
		"00123456789abd",
		"123456789abcdef0",
	}

	// I probably should have saved the shell scripting that was involved in creating these tests
	expected := map[string]map[string]string{
		"0123456789ab": {
			"0123456789ab":     "3473b093f4dbc722b2888a959bbea9900930a37b551a87f0dacb5b8e7cc25716",
			"123456789abd":     "90e6c973cdc0fd7e1e46c175a96b097aa028c609735c7b8e22cc2ad73d4f3562",
			"00123456789abd":   "90e6c973cdc0fd7e1e46c175a96b097aa028c609735c7b8e22cc2ad73d4f3562",
			"0fff12341234":     "531757fcb6b4777079de5c16ec0c7cc34e9d9a87231e45d3880bae20ecfbca6c",
			"ffff12341234":     "a4e46ec489660092000f88f2f313630c198583f4609b1d731b4c12f8a13d1aae",
			"123456789abcdef0": "d469afdb6b53eae515a3b90bd068f4b51a7c07ed3338a5b0f115568f189c92fa",
		},
		"123456789abd": {
			"0123456789ab":     "8316d6bb7c4948281828fc87b0a60b27131147acc9dd3884579dd373bc5fa66c",
			"123456789abd":     "84a9d2f215c13ed60a5163fc1ae80720c5ee38994cb3c9e2c61f1d9c6769fee0",
			"00123456789abd":   "84a9d2f215c13ed60a5163fc1ae80720c5ee38994cb3c9e2c61f1d9c6769fee0",
			"0fff12341234":     "a1ba645a117a5b3f25c092db8de15cd6d1441e65fad076b6a724e9fa799e5e27",
			"ffff12341234":     "dcd2d4db6b6b9374ece8218aa329f0d6af1916e3e7cd648ac69696f7b0fc35c8",
			"123456789abcdef0": "f3b18867043bff3f8f70ded696a8f30641a6e978b64afac268fe5e0c218541b5",
		},
		"00123456789abd": {
			"0123456789ab":     "8316d6bb7c4948281828fc87b0a60b27131147acc9dd3884579dd373bc5fa66c",
			"123456789abd":     "84a9d2f215c13ed60a5163fc1ae80720c5ee38994cb3c9e2c61f1d9c6769fee0",
			"00123456789abd":   "84a9d2f215c13ed60a5163fc1ae80720c5ee38994cb3c9e2c61f1d9c6769fee0",
			"0fff12341234":     "a1ba645a117a5b3f25c092db8de15cd6d1441e65fad076b6a724e9fa799e5e27",
			"ffff12341234":     "dcd2d4db6b6b9374ece8218aa329f0d6af1916e3e7cd648ac69696f7b0fc35c8",
			"123456789abcdef0": "f3b18867043bff3f8f70ded696a8f30641a6e978b64afac268fe5e0c218541b5",
		},
		"0fff12341234": {
			"0123456789ab":     "a8b75aa42a37697190b7ee3d4a94767d824833b09a67f4a000baa91b4c299bbf",
			"123456789abd":     "e3fe08e9dd54a7fc45cef7fce898cfe5d13761180d39ae2ce09d291de84e24f0",
			"00123456789abd":   "e3fe08e9dd54a7fc45cef7fce898cfe5d13761180d39ae2ce09d291de84e24f0",
			"0fff12341234":     "8b71aac3218c8ed169e8ea0a812a6285720cf9ae500213e74597d92035aca3b0",
			"ffff12341234":     "f4f5f8c6136abb8f330c584cc4118ff4ab267a778f647488132e8247918cea5a",
			"123456789abcdef0": "35d468540b4ec5b6d87c892c64c53f12133d95e3f7725738fe6aec849084ad94",
		},
		"ffff12341234": {
			"0123456789ab":     "c64ccc47ad0384b7319e77454c8222360517a187c4a65e14681e896fe33df91c",
			"123456789abd":     "206b4ac4d451dbba7de2f31f321c4cdf08562ba42ef39d447ac74ffa62b4991e",
			"00123456789abd":   "206b4ac4d451dbba7de2f31f321c4cdf08562ba42ef39d447ac74ffa62b4991e",
			"0fff12341234":     "4525eb8e1689800db2cf63545ce2a331e4ffce73dccf4ff9cc76ebb1a4bb1370",
			"ffff12341234":     "a4f7aea26de01ca96c679539ae8a5f85c84885c8df7d22323dcc5225ab5bd782",
			"123456789abcdef0": "20e882a091216d709c6e3e59dcac4068912c82b401412b6c89105e16cd10960a",
		},
		"123456789abcdef0": {
			"0123456789ab":     "d1ffad6424b8e424ab930f37c42523371e639ccd40d25c49683590878345c4c2",
			"123456789abd":     "2765d1ed7b227492795f830e9606875dfc2bb79cb7d047de0d8f57c577bb840e",
			"00123456789abd":   "2765d1ed7b227492795f830e9606875dfc2bb79cb7d047de0d8f57c577bb840e",
			"0fff12341234":     "d522edeb8c365db35685e997840fecc67d0a1edcfd170cf77271c42112959b63",
			"ffff12341234":     "a2758e911a3286c99ab6c630c92cc4fa5330685dafa23a61005f07ccdb42084e",
			"123456789abcdef0": "8c2f9fd27c0044c83e64bc66162be45810cadb85e774fb9ab5eaf26ea68f7fa8",
		},
	}

	s := NewSRPServer(KnownGroups[RFC5054Group4096], v, k)
	for _, A := range testStrings {
		for _, B := range testStrings {
			s.ephemeralPublicA = NumberFromString(A)
			s.ephemeralPublicB = NumberFromString(B)

			u, err := s.calculateU()
			if err != nil {
				t.Errorf("Failed to compute u on (%q, %q): %v", A, B, err)
			}

			// some test on u will happen here
			uHex := hex.EncodeToString(u.Bytes())

			if uHex != expected[A][B] {
				t.Errorf("u(%s,%s) = %s\n\tExpected %s", A, B, uHex, expected[A][B])
			}
		}
	}
}

func TestSRP_Marshal_Unmarshal_Binary(t *testing.T) {
	// Everything here is just to get the server into a state where it has some data associated with this particular
	// exchange. This way it can be marshaled, and we can assert that unmarshalling it retains the data properly.
	var err error
	var A, B *big.Int

	group := RFC5054Group4096
	pw := "SuperSecureP@ssw0rd"
	salt := make([]byte, 16)
	if n, err := rand.Read(salt); err != nil {
		t.Error(err)
	} else if n != 16 {
		t.Error("failed to generate 8 byte salt")
	}
	username := "generic@email.tld"
	x := KDFRFC5054(salt, username, pw) // Really. Don't use this KDF

	client := NewSRPClient(KnownGroups[group], x, nil)
	if client == nil {
		t.Error("couldn't setup client")
	}

	v, err := client.Verifier()
	if err != nil {
		t.Errorf("failed to create verifier: %+v", err)
	}

	A = client.EphemeralPublic()

	server := NewSRPServer(KnownGroups[group], v, nil)
	if err = server.SetOthersPublic(A); err != nil {
		t.Error(err)
	}
	if B = server.EphemeralPublic(); B == nil {
		t.Error("server couldn't make B")
	}
	serverKey, err := server.Key()
	if err != nil || serverKey == nil {
		t.Errorf("something went wrong making server key: %s\n", err)
	}

	// Now actually marshal the server object.
	data, err := server.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to marshal SRP into binary: %+v", err)
	}
	if len(data) == 0 {
		t.Errorf("Resulting byte array was empty")
	}

	newServer := &SRP{} //nolint:exhaustruct
	err = newServer.UnmarshalBinary(data)
	if err != nil {
		t.Errorf("Failed to unmarshal binary data into SRP: %+v", err)
	}

	// Now that we have a new server, have the client do a bit more work; then we will perform the next step on the new
	// server that we have made.
	if err = client.SetOthersPublic(B); err != nil {
		t.Errorf("failed to set others public: %+v", err)
	}
	clientKey, err := client.Key()
	if err != nil || clientKey == nil {
		t.Errorf("something went wrong making server key: %s", err)
	}

	serverProof, err := newServer.M(salt, username)
	if err != nil {
		t.Errorf("failed to create server proof with new server: %+v", serverProof)
	}

	// client tests that the server sent a good proof
	if !client.GoodServerProof(salt, username, serverProof) {
		// Client must bail and not send a its own proof back to the server
		t.Error("bad proof from server")
	}

	// Only after having a valid server proof will the client construct its own
	clientProof, err := client.ClientProof()
	if err != nil {
		t.Errorf("failed to create client proof: %+v", err)
	}

	// client sends its proof to the server. Server checks
	if !newServer.GoodClientProof(clientProof) {
		t.Error("bad proof from client")
	}

	// If we got to this point then that means the server marshalling and unmarshalling works.
}

/**
 ** Copyright 2017, 2020 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
