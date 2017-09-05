package srp

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// These tests are based on SRP Test Vectors
// https://tools.ietf.org/html/rfc5054#appendix-B

var username = "alice"
var password = "password123"

var expectedX = NumberFromString("0x 94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")

var expectedVerifier = hexNumberString(
	"7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812" +
		"9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5" +
		"C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5" +
		"EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78" +
		"E955A5E2 9E7AB245 DB2BE315 E2099AFB")

var a = hexNumberString("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")

var g1024 = &Group{g: big.NewInt(2), N: NumberFromString("0x EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
	"9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
	"8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
	"7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
	"FD5138FE8376435B9FC61D2FC0EB06E3")}

func init() {
	KnownGroups["1024"] = g1024
}

var expectedA = hexNumberString(
	"61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4" +
		"4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC" +
		"8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44" +
		"BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA" +
		"B349EF5D 76988A36 72FAC47B 0769447B")

func hexNumberString(s string) *big.Int {
	result, err := hex.DecodeString(strings.Replace(s, " ", "", -1))
	if err != nil {
		panic(err)
	}
	return NumberFromBytes(result)
}

func TestCalculatesA(t *testing.T) {
	userA, _ := CalculateA("1024", a)
	if fmt.Sprintf("%x", userA) != fmt.Sprintf("%x", expectedA) {
		t.Errorf("userA != expectedA; \n%x\n != \n%x\n", userA, expectedA)
	}
}

// Auth contains information on the type of auth used
type Auth struct {
	Method     string `json:"method"`
	Alg        string `json:"alg"`
	Iterations uint32 `json:"iterations"`
	Salt       string `json:"salt"`
}

func TestVerifier(t *testing.T) {
	salt, err := hex.DecodeString("BEB25379D1A8581EB5A727673A2441EE")
	if err != nil {
		panic(err)
	}

	auth := &Auth{
		Method:     "SRP-1024",
		Alg:        "SRP-HS1",
		Iterations: 0,
		Salt:       string(salt),
	}

	x, err := CalculateX(auth.Method, auth.Alg, username, password, []byte(auth.Salt), int(auth.Iterations), nil)
	if err != nil {
		t.Error(err)
	}

	if fmt.Sprintf("%x", x) != fmt.Sprintf("%x", expectedX) {
		t.Errorf("x != expectedX; \n%x\n != \n%x\n", x, expectedX)
	}

	verifier := CalculateVerifier("1024", x)
	if fmt.Sprintf("%x", verifier) != fmt.Sprintf("%x", expectedVerifier) {
		t.Errorf("verifier != expectedVerifier; \n%x\n != \n%x\n", verifier, expectedVerifier)
	}
}

func TestSRPAgainstSpec(t *testing.T) {
	// Given standard SRP test vectors from http://tools.ietf.org/html/rfc5054#appendix-B
	groupName := "1024"

	x := NumberFromString("0x 94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
	v := NumberFromString("0x " +
		"7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812" +
		"9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5" +
		"C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5" +
		"EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78" +
		"E955A5E2 9E7AB245 DB2BE315 E2099AFB")
	k := NumberFromString("0x 7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")

	// a := NumberFromString("0x 60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
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

	calculatedVerifier := CalculateVerifier(groupName, x)
	if calculatedVerifier.Cmp(v) != 0 {
		t.Error("Verifier calculation is not correct")
	}

	calculatedB := CalculateB(groupName, k, v, b)
	if calculatedB.Cmp(B) != 0 {
		t.Error("B calculation is not correct")
	}

	calculatedSecret, _ := CalculateServerRawKey(groupName, A, v, b, u)
	if calculatedSecret.Cmp(premasterSecret) != 0 {
		t.Error("Premaster secret is not correct")
	}
}

func TestCalculateClientRawKey(t *testing.T) {
	x := NumberFromString("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773")
	a := NumberFromString("f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06")
	B := NumberFromString("780a5495cbf731d2463fd01d28822e7d9ccf697c4239d5151f85666aa06b3767e0301b54cfad3bd2b526d4d8a1d96492e59c8d8ecddca96b7e288f186155ffa57b50df6bc2103b6004400b797334a22d9dd234b40142a5ab714ea6070d2ed55096049f50efba99862b72f7e7aee51ed71ba6663fff570cc713d456316f3535630e87a245f09b0791c6e687baa65bf2dfb5c17e50c250256cdad4c9851a2484e88326888060ae9578b5a60e0c85143b25f4fb4fca794e266a4359642da085672d6a3b881649a387875685aeb1ae3d809bf7818dcad596c6e29d566ae87c0ad645a0fcc2eb4f066c097670adf48cf0954918fda4dc30588261321d592f890eed87a950d387b48cf6b4a49f9d497323f683091ae6a4efe675d6bfc4393c0c3d54c9adad65b8dd3a7b7e85cd5d31e97bebc8f23b370348dab53903ec5085cbf65de5e5491f417e5bf9953f081e788f36c26cbe00664a1256c4befb00765ea7e432af189521442c186f14442b1957e444426f740f363ebda943da2bb3b18a13e2f41be9cc3ca0a1b111f6983f9b8d0ee0f4b573c6042fbc0ca029821ebe517ed0755a94f42d32b0abef9240af0f37b5fe0e90c4ca83acf91d28a7f3acff5657bf69fdb7747e380b23fd437f637da2f7ebcf8733a69a75715fe3894e1799906b48e3ae818332cf5f9533e7af5a1f065f907c8f31fe778fa2da853e69926fc551d6b3ae")
	u := NumberFromString("dad353365f78590c1857b29f16e3a947df4707868e2dd2d2b4eafd35c8c854a1")
	k := NumberFromString("4832374a524b354d344e424a584f42434f45544356584a484641")
	expectedKey := NumberFromString("f6bef3d6fa5a08a849bf61041cd5b3185c16aede851c819a3644fa7e918c4da6")
	key, _ := CalculateClientRawKey("4096", a, B, u, x, k)
	if fmt.Sprintf("%x", key) != fmt.Sprintf("%x", expectedKey) {
		t.Errorf("key doesn't match expected key.\n%x\n!=\n%x", key, expectedKey)
	}
}

// NumberFromString converts a string to a number
func NumberFromString(s string) *big.Int {
	n := strings.Replace(s, " ", "", -1)

	result := new(big.Int)
	result.SetString(strings.TrimPrefix(n, "0x"), 16)

	return result
}

func TestNewSrpClient(t *testing.T) {
	var err error
	x := NumberFromString("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773")
	s := NewSrp(false, true, KnownGroups["4096"], x)

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

	if s.A == nil {
		t.Errorf("A was not calculated")
	}
	if _, err = s.makeVerifer(); err != nil {
		t.Errorf("couldn't make v: %s", err)
	}

	if expectedV4096.Cmp(s.v) != 0 {
		t.Errorf("v mismatch\n\tExpected:\t%s\n\tReceived:\t%s", expectedV4096, s.v)
	}

}

func TestSrpClient1024(t *testing.T) {
	var err error
	x := expectedX
	s := NewSrp(false, true, KnownGroups["1024"], x)

	if _, err = s.makeVerifer(); err != nil {
		t.Errorf("couldn't make v: %s", err)
	}

	if expectedVerifier.Cmp(s.v) != 0 {
		t.Errorf("v mismatch\n\tExpected:\t%s\n\tReceived:\t%s", expectedVerifier, s.v)
	}

}
