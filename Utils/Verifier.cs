using System.Security.Cryptography;
using System.Text;

namespace RsaSha256Signature.Utils
{
    public static class Verifier
    {
        public static bool VerifySignature(string message, string signature)
        {
            // Load the public key in PEM format
            string keysDirectory = Path.Combine(AppContext.BaseDirectory, "Keys");
            string publicKeyPem = File.ReadAllText(Path.Combine(keysDirectory, "publicKey.pem"));

            using (var rsa = RSA.Create())
            {
                // Convert the PEM to byte array
                byte[] publicKeyBytes = ConvertPemToBytes(publicKeyPem, "PUBLIC KEY");

                // Import the public key in X.509 format
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                // Hash the message using SHA256
                var messageBytes = Encoding.UTF8.GetBytes(message);
                var hashBytes = SHA256.Create().ComputeHash(messageBytes);

                // Convert signature from Base64 back to byte array
                var signatureBytes = Convert.FromBase64String(signature);

                // Verify the signature using the public key
                return rsa.VerifyHash(hashBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        private static byte[] ConvertPemToBytes(string pemContent, string keyType)
        {
            string header = $"-----BEGIN {keyType}-----";
            string footer = $"-----END {keyType}-----";

            var start = pemContent.IndexOf(header, StringComparison.Ordinal) + header.Length;
            var end = pemContent.IndexOf(footer, start, StringComparison.Ordinal);

            string base64 = pemContent[start..end].Trim();
            return Convert.FromBase64String(base64);
        }
    }
}
