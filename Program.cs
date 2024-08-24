using RsaSha256Signature.Utils;

// Step 1: Generate RSA Keys in PEM format
KeyGenerator.GenerateKeys();

// The message to be signed
string message = "Hello, World!";

// Step 2: Sign the message
string signature = Signer.SignMessage(message);
Console.WriteLine("Signature: " + signature);

// Step 3: Verify the signature
bool isValid = Verifier.VerifySignature(message, signature);
Console.WriteLine("Is the signature valid? " + isValid);
