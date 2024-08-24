using System.Security.Cryptography;
using System.Text;

namespace RsaSha256Signature.Utils
{
    public static class Signer
    {
        public static string SignMessage(string message)
        {
            // Load the private key in PEM format
            string keysDirectory = Path.Combine(AppContext.BaseDirectory, "Keys");
            string privateKeyPem = File.ReadAllText(Path.Combine(keysDirectory, "privateKey.pem"));

            using (var rsa = RSA.Create())
            {
                // Convert the PEM to byte array
                byte[] privateKeyBytes = ConvertPemToBytes(privateKeyPem, "PRIVATE KEY");

                // Import the private key in PKCS#8 format
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

                // Hash the message using SHA256
                var messageBytes = Encoding.UTF8.GetBytes(message);
                var hashBytes = SHA256.Create().ComputeHash(messageBytes);

                // Sign the hash with the private key
                var signatureBytes = rsa.SignHash(hashBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Convert the signature to Base64 for display and transmission
                return Convert.ToBase64String(signatureBytes);
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
