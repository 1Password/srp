package srp

import (
	"crypto/aes"
	"crypto/cipher"
	rand "crypto/rand"
	"fmt"
	"log"
	"math/big"
)

// ExampleServerClientKey is an example
func Example() {

	// This example has both a server and the corresponding client live
	// in the same function. That is not something you would normally do.
	// Normally, you would be running one side (client or server) only.
	// If I understand channels better, I could probably set up a more
	// realistic example.

	var err error
	var A, B *big.Int

	/*** Part 1: First encounter. Enrollment ***/

	// On first encounter between client and server, they will negotiate
	// an SRP group to use. We will assume that they have settled on
	// RFC5054Group3072

	group := RFC5054Group3072

	// The client will need a password from the user and will also need
	// a salt.

	pw := "Fido1961!" // It's the "!" that makes this password super secure

	// Generate 8 bytes of random salt. Be sure to use crypto/rand for all
	// of your random number needs
	salt := make([]byte, 8)
	rand.Read(salt)

	username := "fred@fred.example"

	// You would use a better Key Derivation Function than this one
	x := KDFRFC5054(salt, username, pw) // Really. Don't use this KDF

	// this is still our first use scenario, but the client needs to create
	// an SRP client to generate the verifier.
	firstClient := NewSRPClient(KnownGroups[group], x, nil)
	if firstClient == nil {
		fmt.Println("couldn't setup client")
	}
	v, err := firstClient.Verifier()
	if err != nil {
		fmt.Println(err)
	}

	// Now the client has all it needs to enroll with the server.
	// Client sends salt, username, and v to the server

	// Server will store long term the salt, username, an identifier for the SRP group
	// used and v. It should store v securely.

	/*** Part 2: An authentication session ***/

	// Some time later, we actually want to authenticate with this stuff
	// Client and server may talk. Depending on what the client has locally,
	// The client may need to be told it's salt, and the SRP group to use
	// But here we will assume that that the client knows this, and already has
	// computed x.

	client := NewSRPClient(KnownGroups[group], x, nil)

	// The client will need to send its ephemeral public key to the server
	// so we fetch that now.
	A = client.EphemeralPublic()

	// Now it is time for some stuff (though not much) on the server.
	server := NewSRPServer(KnownGroups[group], v, nil)
	if server == nil {
		fmt.Println("Couldn't set up server")
	}

	// The server will get A (clients ephemeral public key) from the client
	// which the server will set using SetOthersPublic

	// Server MUST check error status here as defense against
	// a malicious A sent by client.
	if err = server.SetOthersPublic(A); err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// server sends its ephemeral public key, B, to client
	// client sets it as others public key.
	if B = server.EphemeralPublic(); B == nil {
		fmt.Println("server couldn't make B")
	}

	// server can now make the key.
	serverKey, err := server.Key()
	if err != nil || serverKey == nil {
		fmt.Printf("something went wrong making server key: %s\n", err)
	}

	// Once the client receives B from the server it can set it.
	// Client should check error status here as defense against
	// a malicious B sent from server
	if err = client.SetOthersPublic(B); err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// client can now make the session key
	clientKey, err := client.Key()
	if err != nil || clientKey == nil {
		fmt.Printf("something went wrong making server key: %s", err)
	}

	/*** Part 3: Server and client prove they have the same key ***/

	// Server computes a proof, and sends it to the client

	serverProof, err := server.M(salt, username)
	if err != nil {
		fmt.Println(err)
	}

	// client tests tests that the server sent a good proof
	if !client.GoodServerProof(salt, username, serverProof) {
		err = fmt.Errorf("bad proof from server")
		fmt.Println(err)
		// Client must bail and not send a its own proof back to the server
		log.Fatal(err)
	}

	// Only after having a valid server proof will the client construct its own
	clientProof, err := client.ClientProof()
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	// client sends its proof to the server. Server checks
	if !server.GoodClientProof(clientProof) {
		err = fmt.Errorf("bad proof from client")
		fmt.Println(err)
		log.Fatal(err)
	}

	/*** Part 4: Server and Client exchange secret messages ***/

	// Once you have confirmed that client and server are using the same key
	// (thus proving that x and v have the right relation to each other)
	// we can use that key to encrypt stuff.

	// Let's have it be a missive from the server to the client

	// server sets up a block cipher with the key
	serverBlock, _ := aes.NewCipher(serverKey) // set with server's key
	serverCryptor, _ := cipher.NewGCM(serverBlock)

	// The client can set up its own cryptor. Note that it uses
	// the key that it (the client) got from SRP
	clientBlock, _ := aes.NewCipher(clientKey) // with the Client's key
	clientCryptor, _ := cipher.NewGCM(clientBlock)

	// We will use GCM with a 12 byte nonce for this example
	// NEVER use the same nonce twice with the same key. Never.
	nonce := make([]byte, 12)
	rand.Read(nonce)

	plaintext := []byte("Hi client! Will you be my Valentine?")
	ciphertext := serverCryptor.Seal(nil, nonce, plaintext, nil)
	// You can use the same serverCryptor many times within a session,
	// (up to about 2^32) for different encryptions
	// but you MUST use a new nonce for each encryption.

	// Server sends the the ciphertext and the nonce to the client

	message, err := clientCryptor.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("Decryption failed: %s", err)
		log.Fatal(err)
		// if decryption fails, do not trust anything about ciphertext
	}

	// If the message is successfully decrypted, then client and server
	// can talk to each other using the key they derived
	fmt.Printf("S -> C: %s\n", message)
	// Output: Hi client! Will you be my Valentine?

	// Client must generate a new nonce for all messages it sends.
	// It MUST NOT reuse the nonce that was used in the message
	// it received when encrypting a different message.

	rand.Read(nonce) // get a fresh nonce
	reply := []byte("Send me chocolate, not bits!")

	replyCipherText := clientCryptor.Seal(nil, nonce, reply, nil)
	// Note that this is a new nonce.

	// client sends the new nonce and the reply to the server.

	plainReply, err := serverCryptor.Open(nil, nonce, replyCipherText, nil)
	if err != nil {
		fmt.Printf("Decryption failed: %s", err)
		log.Fatal(err)
	}
	fmt.Printf("C -> S: %s\n", plainReply)
	// Output: S -> C: Hi client! Will you be my Valentine?
	// C -> S: Send me chocolate, not bits!
}

/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
