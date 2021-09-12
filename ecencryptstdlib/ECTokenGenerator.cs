using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ecencryptstdlib
{
    public class EdgeCastKey
    {
        public EdgeCastKey(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException(paramName: nameof(value));
            }

            using var sha256 = SHA256.Create();
            byte[] keyBytes = sha256.ComputeHash(value.ToUTF8Bytes());

            KeyParameter = new(keyBytes);
        }

        public KeyParameter KeyParameter { get; }
    }

    public class EdgeCastToken
    {
        public EdgeCastToken(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException(paramName: nameof(value));
            }
            if (value.Length > 512)
            {
                throw new ArgumentException("Token exceeds maximum of 512 characters.", paramName: nameof(value));
            }

            Value = value;
        }

        public string Value { get; }

        public static EdgeCastToken Create(string value) => new(value);
    }

    /// <summary>
    /// ECTokenGenerator for .NET Standard Library 1.4
    /// ported and extended by Andreas Pollak (SpectoLogic)
    /// </summary>
    public static class ECTokenGenerator
    {
        private static EdgeCastToken AsToken(this string val) => new(val);

        /// <summary>
        /// This helper methods allows to create expiring CDN encryption tokens
        /// https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth
        /// </summary>
        /// <param name="key">Encyption Secret</param>
        /// <param name="expirationTimeSpan">Timespan from UTCNow when token should expire</param>
        /// <param name="clientIPAddress">restricts access to specified requester's IP address. Both IPV4 and IPV6 are supported. You can specify single request IP address or IP subnet Example: "13.141.12.2/20" </param>
        /// <param name="allowedCountries">Comma separated list or null, Example: "US,FR" </param>
        /// <param name="deniedCountries">Comma separated list of countries you want to block or null, Example: "US,FR" </param>
        /// <param name="allowedReferrers">Comma separated list of allowed referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="deniedReferrers">Comma separated list of denied referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="allowedProtocol">Only allows requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="deniedProtocol">Denies requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="allowedUrls">allows you to tailor tokens to a particular asset or path. It restricts access to requests whose URL start with a specific relative path. You can input multiple paths separating each path with a comma. URLs are case-sensitive. Depending on the requirement, you can set up different value to provide different level of access</param>
        /// <returns></returns>
        public static EdgeCastToken EncryptV3(EdgeCastKey key,
                TimeSpan expirationTimeSpan,
                string clientIPAddress = null,
                string allowedCountries = null,
                string deniedCountries = null,
                string allowedReferrers = null,
                string deniedReferrers = null,
                string allowedProtocol = null,
                string deniedProtocol = null,
                string allowedUrls = null)
        {
            return EncryptV3(
                key: key,
                expirationTime: DateTime.UtcNow + expirationTimeSpan,
                clientIPAddress: clientIPAddress,
                allowedCountries: allowedCountries,
                deniedCountries: deniedCountries,
                allowedReferrers: allowedReferrers,
                deniedReferrers: deniedReferrers,
                allowedProtocol: allowedProtocol,
                deniedProtocol: deniedProtocol,
                allowedUrls: allowedUrls);
        }

        /// <summary>
        /// This helper methods allows to create expiring CDN encryption tokens
        /// https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth
        /// </summary>
        /// <param name="key">Encyption Secret</param>
        /// <param name="expirationTimeSpan">Absolute time when token should expire</param>
        /// <param name="clientIPAddress">restricts access to specified requester's IP address. Both IPV4 and IPV6 are supported. You can specify single request IP address or IP subnet Example: "13.141.12.2/20" </param>
        /// <param name="allowedCountries">Comma separated list or null, Example: "US,FR" </param>
        /// <param name="deniedCountries">Comma separated list of countries you want to block or null, Example: "US,FR" </param>
        /// <param name="allowedReferrers">Comma separated list of allowed referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="deniedReferrers">Comma separated list of denied referrers , Example: "www.contoso.com,*.consoto.com,missing" </param>
        /// <param name="allowedProtocol">Only allows requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="deniedProtocol">Denies requests from specified protocol, Example: "http" or "https" </param>
        /// <param name="allowedUrls">allows you to tailor tokens to a particular asset or path. It restricts access to requests whose URL start with a specific relative path. You can input multiple paths separating each path with a comma. URLs are case-sensitive. Depending on the requirement, you can set up different value to provide different level of access</param>
        /// <returns></returns>
        public static EdgeCastToken EncryptV3(EdgeCastKey key,
            DateTime expirationTime,
            string clientIPAddress = null,
            string allowedCountries = null,
            string deniedCountries = null,
            string allowedReferrers = null,
            string deniedReferrers = null,
            string allowedProtocol = null,
            string deniedProtocol = null,
            string allowedUrls = null)
        {
            /// ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com"
            /// php -d extension=.libs/ectoken.so example.php
            /// php -d extension=.libs/ectoken.so -r '$token = ectoken_encrypt_token("12345678", "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com"); echo $token;'

            static string getEpoch(DateTime t) => ((int)t.Subtract(new DateTime(1970, 1, 1)).TotalSeconds).ToString();

            EdgeCastToken t = new(string.Join('&', new[] {
                ("ec_expire",        getEpoch(expirationTime)),
                ("ec_clientip",      clientIPAddress),
                ("ec_country_allow", allowedCountries), ("ec_country_deny",  deniedCountries),
                ("ec_ref_allow",     allowedReferrers), ("ec_ref_deny",      deniedReferrers),
                ("ec_proto_allow",   allowedProtocol), ("ec_proto_deny",    deniedProtocol),
                ("ec_url_allow",     allowedUrls),
            }
            .Where(i => !string.IsNullOrEmpty(i.Item2))
            .Select(i => $"{i.Item1}={i.Item2}")
            .ToArray()));

            return t.EncryptV3(key);
        }

        // make sure the user didn't pass in ec_secure=1
        // older versions of ecencrypt required users to pass this in
        // current users should not pass in ec_secure
        public static EdgeCastToken EncryptV3(this EdgeCastToken token, EdgeCastKey key)
            => token
                .Value
                .Replace("ec_secure=1", "")
                .Replace("&&", "&")
                .ToUTF8Bytes()
                .AESGCMEncrypt(key)
                .ToBase64()
                .AsToken();

        /// <summary>
        /// Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="token">The encrypted message.</param>
        /// <param name="key">The key.</param>        
        /// <returns>Decrypted Message</returns>
        public static EdgeCastToken DecryptV3(this EdgeCastToken token, EdgeCastKey key)
            => token
                .Value
                .FromBase64()
                .AESGCMDecrypt(key)
                .FromUTF8Bytes()
                .AsToken();

        #region Encrypt V3-AESGCM

        const int NonceByteSize = 12;

        private static Func<byte[]> CreateIVCreator()
        {
            SecureRandom r = new();
            return () =>
            {
                var iv = new byte[NonceByteSize];
                r.NextBytes(iv, 0, iv.Length);
                return iv;
            };
        }
        private static readonly Func<byte[]> CreateIV = CreateIVCreator();

        /// <summary>Encryption And Authentication (AES-GCM) of a UTF8 string.</summary>
        /// <param name="strToken">Token to Encrypt.</param>
        /// <param name="key">The key.</param>         
        /// <returns>Encrypted Message</returns>
        /// <remarks>Adds overhead of (Optional-Payload + BlockSize(16) + Message +  HMac-Tag(16)) * 1.33 Base64</remarks>
        private static byte[] AESGCMEncrypt(this byte[] strToken, EdgeCastKey key)
        {
            byte[] iv = CreateIV();
            GcmBlockCipher cipher = new(new AesEngine());
            ParametersWithIV parameters = new(key.KeyParameter, iv);
            cipher.Init(forEncryption: true, parameters: parameters);

            var cipherText = new byte[cipher.GetOutputSize(strToken.Length)];
            var len = cipher.ProcessBytes(strToken, 0, strToken.Length, cipherText, 0);
            _ = cipher.DoFinal(cipherText, len);
            using MemoryStream combinedStream = new();
            using (BinaryWriter binaryWriter = new (combinedStream))
            {
                binaryWriter.Write(iv);
                binaryWriter.Write(cipherText);
            }
            return combinedStream.ToArray();
        }

        /// <summary>Decryption & Authentication (AES-GCM) of a UTF8 Message</summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The key.</param>
        /// <returns>Decrypted Message</returns>
        public static byte[] AESGCMDecrypt(this byte[] encryptedMessage, EdgeCastKey key)
        {
            Console.WriteLine(Convert.ToBase64String(encryptedMessage));
            Console.WriteLine(Convert.ToBase64String(key.KeyParameter.GetKey()));
            try
            {
                using MemoryStream cipherStream = new(encryptedMessage);
                using BinaryReader cipherReader = new(cipherStream);

                //Grab Nonce
                var iv = cipherReader.ReadBytes(NonceByteSize);
                GcmBlockCipher cipher = new(new AesEngine());
                ParametersWithIV parameters = new(key.KeyParameter, iv);
                cipher.Init(forEncryption: false, parameters: parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - NonceByteSize);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
                var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                cipher.DoFinal(plainText, len);
                return plainText;
            }
            catch (InvalidCipherTextException)
            {
                return Array.Empty<byte>();
            }
        }

        internal static byte[] ToUTF8Bytes(this string str)
            => Encoding.UTF8.GetBytes(str);

        private static string FromUTF8Bytes(this byte[] bytes)
            => Encoding.UTF8.GetString(bytes);

        private static string ToBase64(this byte[] arg)
            => Convert.ToBase64String(arg) // Regular base64 encoder
                .Split('=')[0] // Remove any trailing '='s
                .Replace('+', '-') // 62nd char of encoding
                .Replace('/', '_'); // 63rd char of encoding                      

        private static byte[] FromBase64(this string arg)
        {
            string s = arg
                .Replace('-', '+') // 62nd char of encoding
                .Replace('_', '/'); // 63rd char of encoding

            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new Exception("Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        #endregion
    }
}
