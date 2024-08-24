using System.Security.Cryptography;
using System.Text;

namespace RsaSha256Signature.Utils
{
    public static class KeyGenerator
    {
        public static void GenerateKeys()
        {
            string keysDirectory = Path.Combine(AppContext.BaseDirectory, "Keys");
            if (!Directory.Exists(keysDirectory))
            {
                Directory.CreateDirectory(keysDirectory);
            }

            using (var rsa = RSA.Create(2048))
            {
                // Export the private key in PEM format
                var privateKeyPem = ExportPrivateKeyToPEM(rsa);
                File.WriteAllText(Path.Combine(keysDirectory, "privateKey.pem"), privateKeyPem);

                // Export the public key in PEM format
                var publicKeyPem = ExportPublicKeyToPEM(rsa);
                File.WriteAllText(Path.Combine(keysDirectory, "publicKey.pem"), publicKeyPem);

                Console.WriteLine("Keys generated and saved in PEM format.");
            }
        }

        private static string ExportPrivateKeyToPEM(RSA rsa)
        {
            var privateKeyBytes = rsa.ExportRSAPrivateKey();
            return "-----BEGIN PRIVATE KEY-----\n" + Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PRIVATE KEY-----";
        }

        private static string ExportPublicKeyToPEM(RSA rsa)
        {
            var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
            return "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(publicKeyBytes, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PUBLIC KEY-----";
        }

        public static string ConvertToPem(RSAParameters keyParams, bool includePrivateKey)
        {
            var sb = new StringBuilder();

            if (includePrivateKey)
            {
                sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
                sb.AppendLine(Convert.ToBase64String(EncodePrivateKey(keyParams), Base64FormattingOptions.InsertLineBreaks));
                sb.AppendLine("-----END RSA PRIVATE KEY-----");
            }
            else
            {
                // For public key, we need to encode in X.509 (SubjectPublicKeyInfo) format
                sb.AppendLine("-----BEGIN PUBLIC KEY-----");
                sb.AppendLine(Convert.ToBase64String(EncodePublicKey(keyParams), Base64FormattingOptions.InsertLineBreaks));
                sb.AppendLine("-----END PUBLIC KEY-----");
            }

            return sb.ToString();
        }

        // Encode the private key to PKCS#1 format
        private static byte[] EncodePrivateKey(RSAParameters keyParams)
        {
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write((byte)0x30); // SEQUENCE
                    using (var innerStream = new MemoryStream())
                    {
                        using (var innerWriter = new BinaryWriter(innerStream))
                        {
                            EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                            EncodeIntegerBigEndian(innerWriter, keyParams.Modulus);
                            EncodeIntegerBigEndian(innerWriter, keyParams.Exponent);
                            EncodeIntegerBigEndian(innerWriter, keyParams.D);
                            EncodeIntegerBigEndian(innerWriter, keyParams.P);
                            EncodeIntegerBigEndian(innerWriter, keyParams.Q);
                            EncodeIntegerBigEndian(innerWriter, keyParams.DP);
                            EncodeIntegerBigEndian(innerWriter, keyParams.DQ);
                            EncodeIntegerBigEndian(innerWriter, keyParams.InverseQ);

                            var length = (int)innerStream.Length;
                            EncodeLength(writer, length);
                            writer.Write(innerStream.ToArray(), 0, length);
                        }
                    }
                }

                return ms.ToArray();
            }
        }

        // Encode the public key to X.509 format
        private static byte[] EncodePublicKey(RSAParameters keyParams)
        {
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write((byte)0x30); // SEQUENCE
                    using (var innerStream = new MemoryStream())
                    {
                        using (var innerWriter = new BinaryWriter(innerStream))
                        {
                            // SEQUENCE: AlgorithmIdentifier
                            EncodeLength(innerWriter, 13);
                            innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER (1.2.840.113549.1.1.1 - rsaEncryption)
                            EncodeLength(innerWriter, 9);
                            innerWriter.Write(new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 });
                            innerWriter.Write((byte)0x05); // NULL
                            EncodeLength(innerWriter, 0);

                            // BIT STRING: SubjectPublicKeyInfo
                            var pubKey = EncodeRSAPublicKey(keyParams);
                            EncodeLength(innerWriter, pubKey.Length + 1);
                            innerWriter.Write((byte)0x00); // Unused bits
                            innerWriter.Write(pubKey, 0, pubKey.Length);

                            var length = (int)innerStream.Length;
                            EncodeLength(writer, length);
                            writer.Write(innerStream.ToArray(), 0, length);
                        }
                    }
                }

                return ms.ToArray();
            }
        }

        // Encode the RSA public key
        private static byte[] EncodeRSAPublicKey(RSAParameters keyParams)
        {
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write((byte)0x30); // SEQUENCE
                    using (var innerStream = new MemoryStream())
                    {
                        using (var innerWriter = new BinaryWriter(innerStream))
                        {
                            EncodeIntegerBigEndian(innerWriter, keyParams.Modulus);
                            EncodeIntegerBigEndian(innerWriter, keyParams.Exponent);

                            var length = (int)innerStream.Length;
                            EncodeLength(writer, length);
                            writer.Write(innerStream.ToArray(), 0, length);
                        }
                    }
                }

                return ms.ToArray();
            }
        }

        // Encode an integer as a DER-encoded BigEndian
        private static void EncodeIntegerBigEndian(BinaryWriter writer, byte[] value)
        {
            writer.Write((byte)0x02); // INTEGER
            EncodeLength(writer, value.Length + (value[0] >= 0x80 ? 1 : 0));
            if (value[0] >= 0x80) writer.Write((byte)0x00);
            writer.Write(value);
        }

        // Encode the length of the DER-encoded structure
        private static void EncodeLength(BinaryWriter writer, int length)
        {
            if (length < 0x80)
            {
                writer.Write((byte)length);
            }
            else
            {
                var temp = length;
                var lenBytes = new List<byte>();

                while (temp > 0)
                {
                    lenBytes.Insert(0, (byte)(temp & 0xFF));
                    temp >>= 8;
                }

                writer.Write((byte)(lenBytes.Count | 0x80));
                writer.Write(lenBytes.ToArray());
            }
        }
    }
}
