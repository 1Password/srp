package srp

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

func Example_serverClientMatch() {

	// This example has both a server and the corresponding client live
	// in the same function. That is not something you would normally do.
	// Normally, you would be running one side (client or server) only.
	// If I understand channels better, I could probably set up a more
	// realistic example.

	var err error
	var A, B *big.Int

	// In this example, the client and the server will both manually
	// set the value for instead of this being calculated internally.
	// k doesn't need to be secret, but it should be different from
	// session to session, and the client and server need the same one.
	khex := "7556AA045AEF2CDD07ABAF0F665C3E818913186F"
	k, _ := hex.DecodeString(khex)
	// to allow me to declare without using
	_ = khex
	_ = k

	group := KnownGroups[RFC5054Group4096]

	// client x would normally be derived from some KDF or stored locally long term on client system, but we are just
	x := NumberFromString("740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773")

	// server verifier would be stored long term on server. It is intially computed by client
	v := NumberFromString("0d05240ed513a4f267608e64cf2a84f5106741ddbf1435707a84f530207409d7af1e671182f9d77855b61c628df2b8f6ba8e9b6068fbc84fab80b4542f44c666e17358ebffa8d6fb00fd7037ab9ee450413f240ab1e4b586e48bf43ce38f41ad7e406d0150ea83c8f216db4dec06ec5d9fb1cbfd049f70438fc14a2faa2a920ad1b298bb1c70989d17163cf52632f202e77824d71c0ff2dd2ef63ebdcd6140beb471b9a7f7b14e2d45478994dac95d27f2b45404e564c90eb65655bf6a789bfd665035f711b7cf766a380b921a666dfcfee0238b27eafdd8a953a50cc2c4f291458d48ef9fd0740da59aa325b9165ebb97d125511b03e1056bd448b322d7d250816783462cff6f9ecd40813522dac10329b7c4bcd0c8f0ceec2eb2c46ba442ac62a84994e2fcdb94cbfe057cad578c5e4d28822cd283e8430b8a1e1106f6e2536e8596b8a0de46717fbd4e9f06b796364aa930bbcf87433cbbbf15b077b2998569027edcae71d09112857d0fac06d9f9f70371f43f8581a229c290ade4e63251f8d8a0c961e20d357069472db3ff422c3ecacf6ff9b2af54003d6aa344a37e7a7f04a1a667d5299475cea6b02c09b58505c895efbd86703a0a375ccdf81616e8bee6cfc947467c4bcbe4a7d3e245df32cd7192e212ffe635ff8ac9727d6fe05ede8338f6f3bc18b5359ea8afc13ce3952cd426fb0934c5ea54e71e10bf81028f")

	client := NewSRP(false, group, x)
	if client == nil {
		fmt.Println("couldn't setup client")
	}

	// client will need to send its public ephemeral key to server, so let's
	// get that now.
	if A = client.EphemeralPublic(); A == nil {
		fmt.Println("client couldn't make A")
	}

	server := NewSRP(true, group, v)
	if server == nil {
		fmt.Println("Couldn't set up server")
	}

	// Client will send its Ephemeral Public key to server,
	// which the server will set using SetOthersPublic

	// Server MUST check error status here as defense against
	// a malicious A sent by client.
	if err = server.SetOthersPublic(A); err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// If manually setting k, server must do so early
	if _, err = server.SetKFromHex(khex); err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// server can now make the key.
	serverKey, err := server.MakeKey()
	if err != nil || serverKey == nil {
		fmt.Printf("something went wrong making server key: %s\n", err)
	}

	// server sends its ephemeral public key, B, to client
	// client sets it as others public key.

	if B = server.EphemeralPublic(); B == nil {
		fmt.Println("server couldn't make B")
	}

	// Client should check error status here as defense against
	// a malicious B sent from server
	if err = client.SetOthersPublic(B); err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	client.SetKFromHex(khex)
	// client can now make the session key
	clientKey, err := client.MakeKey()
	if err != nil || clientKey == nil {
		fmt.Printf("something went wrong making server key: %s", err)
	}

	// In normal usage, server and client would send challenges to prove
	// that each know the same key. Here we have both in the same space, so
	// we just compare

	if serverKey.Cmp(clientKey) == 0 {
		fmt.Println("Keys match")
	} else {
		fmt.Println("Uh oh")
	}
	// Output: Keys match
}
