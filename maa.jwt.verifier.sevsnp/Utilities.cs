// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Cryptography;
using System.Formats.Asn1;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using Newtonsoft.Json;
using PeterO.Cbor;

namespace maa.jwt.verifier.sevsnp
{
    public static class JwtUtils
    {
        /// <summary>
        /// Retrieves the JSON Web Key Set (JWKS) from the 'jku' (JWK Set URL) specified in the JWT header.
        /// </summary>
        /// <param name="jwt">The parsed JwtSecurityToken.</param>
        /// <returns>The raw JWKS JSON string.</returns>
        /// <exception cref="Exception">Throws if 'jku' header is missing, invalid, or if the endpoint cannot be retrieved.</exception>
        public static async Task<string> GetSigningCertificatesAsync(JwtSecurityToken jwt)
        {
            if (!jwt.Header.TryGetValue("jku", out object? jkuValue) || jkuValue is not string jkuUrl)
            {
                throw new Exception("Missing or invalid 'jku' header in JWT.");
            }

            Console.WriteLine($"JWT Signing Certificates Endpoint (jku): {jkuUrl}");

            using var httpClient = new HttpClient();
            string jwkSetJson = await httpClient.GetStringAsync(jkuUrl)
                ?? throw new Exception($"Failed to retrieve JWK set from the 'jku' endpoint: {jkuUrl}");

            return jwkSetJson;
        }

        public static void PrintKeyHash(X509Certificate2 cert)
        {
            var hash = Crypto.HashPemWithNullTerminator(cert);
            Console.WriteLine($"Null Terminated SHA-256 Hash: {hash}");
        }

        public static List<X509Certificate2> RetrieveSelfSignedSigningCertificates(string certificatesString)
        {
            try
            {
                var certificatesJson = JsonConvert.DeserializeObject<dynamic>(certificatesString);
                List<X509Certificate2> certificates = [];

                if (certificatesJson?.keys != null)
                {
                    foreach (var certificate in certificatesJson.keys)
                    {
                        var certBase64 = certificate?.x5c[0]?.ToString();
                        if (!string.IsNullOrEmpty(certBase64))
                        {
                            var certBytes = Convert.FromBase64String(certBase64);
                            var x509Certificate = new X509Certificate2(certBytes);

                            // Filter to only self-signed certificates (where subject equals issuer)
                            if (x509Certificate.Subject == x509Certificate.Issuer)
                            {
                                certificates.Add(x509Certificate);

                                // TODO OLGA - delete this
                                //var kid = certificate?.kid?.ToString();
                                //Console.WriteLine($"Key ID: {kid}");
                                //PrintKeyHash(x509Certificate);
                            }
                        }
                    }
                }

                return certificates;
            }
            catch (Exception ex)
            {
                throw new Exception($"Certificate Retrieval Error: {ex} for certificate {certificatesString}");
            }
        }
    }

    public class Crypto
    {
        public static string GetPemFromX509Certificate2(X509Certificate2 cert)
        {
            string pem = RsaToPem(cert.GetRSAPublicKey());
            return pem;
        }

        public static string RsaToPem(RSA? rsa)
        {
            if (rsa == null)
            {
                throw new Exception("RsaToPem - rsa is null.");
            }

            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var base64 = Convert.ToBase64String(publicKey);

            const int LineLength = 64;
            var sb = new StringBuilder();

            sb.Append("-----BEGIN PUBLIC KEY-----\n");

            for (int i = 0; i < base64.Length; i += LineLength)
            {
                int chunkSize = Math.Min(LineLength, base64.Length - i);
                sb.Append(base64.Substring(i, chunkSize)).Append('\n');
            }

            sb.Append("-----END PUBLIC KEY-----\n");
            var pem = sb.ToString();
            return pem;
        }

        public static string HashPemWithNullTerminator(RSA? rsa)
        {
            if (rsa == null)
            {
                throw new Exception("GetHashWithNullTerminator - rsa is null.");
            }
            string pem = RsaToPem(rsa);

            byte[] pemBytes = Encoding.UTF8.GetBytes(pem);
            byte[] bytesWithNull = new byte[pemBytes.Length + 1];
            Buffer.BlockCopy(pemBytes, 0, bytesWithNull, 0, pemBytes.Length);
            bytesWithNull[^1] = 0;

            string pemHashHex = Convert.ToHexString(SHA256.HashData(bytesWithNull)).ToLowerInvariant();
            return pemHashHex;
        }

        public static string HashPemWithNullTerminator(X509Certificate2 cert)
        {
            return HashPemWithNullTerminator(cert.GetRSAPublicKey());
        }

        public static byte[] PemStringToRsaBytes(string pem)
        {
            using var rsa = PemStringToRsa(pem);
            return rsa.ExportSubjectPublicKeyInfo();
        }

        public static RSA PemStringToRsa(string pem)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem.ToCharArray());
            return rsa;
        }

        public static bool AreEqual(RSA a, RSA b)
        {
            if (a == null || b == null)
            {
                return false;
            }

            var aParams = a.ExportParameters(false);
            var bParams = b.ExportParameters(false);

            return aParams.Modulus != null &&
                   bParams.Modulus != null &&
                   aParams.Exponent != null &&
                   bParams.Exponent != null &&
                   aParams.Modulus.SequenceEqual(bParams.Modulus) &&
                   aParams.Exponent.SequenceEqual(bParams.Exponent);
        }

        public static string GetExtensionValueAsUtf8StringByOid(X509Certificate2 certificate, string oid)
        {
            var extension = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(ext => ext.Oid?.Value == oid)
                            ?? throw new Exception($"Failed to retrieve X509 certificate extension with OID {oid}.");
            var asnValue = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            return asnValue.ReadCharacterString(UniversalTagNumber.UTF8String);
        }

        public static JObject GetExtensionValueAsJObject(X509Certificate2 certificate, string oid)
        {
            var extensionValue = Crypto.GetExtensionValueAsUtf8StringByOid(certificate, Constants.MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID);
            var reportJson = JObject.Parse(extensionValue) ?? throw new Exception($"Failed to parse X509 certificate extension value OID '{oid}' as a JSON object.");
            return reportJson;
        }

        public static string GetReportValueRaw(JObject reportJson, string reportKey)
        {
            var keyValueRaw = reportJson[reportKey]?.ToString();
            if (string.IsNullOrEmpty(keyValueRaw))
            {
                throw new Exception($"Failed to get value '{reportKey}' from the report. '{reportKey}' is null or missing in the report JSON object '{reportJson}'.");
            }
            return keyValueRaw;
        }

        public static byte[] GetReportValueDecodedBytes(JObject reportJson, string reportKey)
        {
            var keyValueEncoded = GetReportValueRaw(reportJson, reportKey);
            var bytes = Base64UrlEncoder.DecodeBytes(keyValueEncoded);
            return bytes;
        }

        public static string GetReportValueDecodedString(JObject reportJson, string reportKey)
        {
            var keyValueEncoded = GetReportValueRaw(reportJson, reportKey);
            var keyValueString = Base64UrlEncoder.Decode(keyValueEncoded);
            return keyValueString;
        }

        public enum CertValidationTarget
        {
            Leaf,
            Root
        }

        public static bool BuildAndValidateCertChain(
            List<X509Certificate2>? certs,
            RSA[] trustedAnchors,
            CertValidationTarget target)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(certs?.ToArray() ?? []);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            var leafCert = certs?.FirstOrDefault();
            if (leafCert == null || !chain.Build(leafCert))
            {
                Console.WriteLine("Failed to build certificate chain.");
                return false;
            }

            X509Certificate2 certToValidate = target switch
            {
                CertValidationTarget.Leaf => chain.ChainElements[0].Certificate,
                CertValidationTarget.Root => chain.ChainElements[^1].Certificate,
                _ => throw new InvalidOperationException("Unknown validation target")
            };

            var certPublicKey = certToValidate.GetRSAPublicKey();
            if (certPublicKey == null)
            {
                Console.WriteLine("Selected certificate does not contain an RSA public key.");
                return false;
            }

            foreach (var trustedKey in trustedAnchors)
            {
                Console.WriteLine($"\nComparing public keys:\n");
                var trustedKeyPem = Crypto.RsaToPem(trustedKey);
                Console.WriteLine($"\tTrusted key PEM \n{trustedKeyPem}");
                var certPublicKeyPem = Crypto.RsaToPem(certPublicKey);
                Console.WriteLine($"\t{target} Cert key PEM to verify\n{certPublicKeyPem}");

                if (Crypto.AreEqual(certPublicKey, trustedKey))
                {
                    Console.WriteLine("Certification chain is valid and roots to a trusted key.");
                    return true;
                }
            }

            return false;
        }

        public static List<X509Certificate2> ExtractX509CertificatesFromBytes(byte[] coseSign1Bytes)
        {
            // Parse the COSE_Sign1 message as CBOR array
            CBORObject cose = CBORObject.DecodeFromBytes(coseSign1Bytes);

            if (cose.Type != CBORType.Array || cose.Count != 4)
            {
                throw new Exception("Invalid COSE_Sign1 structure. Expected array of 4 elements.");
            }

            // COSE_Sign1 structure: [ protected, unprotected, payload, signature ]
            CBORObject protectedBytes = cose[0];
            CBORObject unprotectedMap = cose[1];

            // Decode protected headers (they're in a bstr)
            CBORObject protectedHeaders = CBORObject.DecodeFromBytes(protectedBytes.GetByteString());

            // Look in protected or unprotected for x5chain (header key 33)
            CBORObject? x5Chain = null;
            if (protectedHeaders.ContainsKey(CBORObject.FromObject(33)))
                x5Chain = protectedHeaders[CBORObject.FromObject(33)];
            else if (unprotectedMap.ContainsKey(CBORObject.FromObject(33)))
                x5Chain = unprotectedMap[CBORObject.FromObject(33)];

            if (x5Chain == null || x5Chain.Type != CBORType.Array || x5Chain.Count == 0)
            {
                throw new Exception("x5chain (header key 33) not found.");
            }

            List<X509Certificate2> certs = [];
            int count = x5Chain.Count;
            for (int i = 0; i < count; ++i)
            {
                certs.Add(new X509Certificate2(x5Chain[i].GetByteString()));
            }
            return certs;
        }
    }
}