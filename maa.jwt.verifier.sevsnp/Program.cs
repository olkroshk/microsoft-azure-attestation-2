// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;
using Com.AugustCellars.COSE;
using PeterO.Cbor;

namespace maa.jwt.verifier.sevsnp
{
    public class Program
    {

        public static async Task Main(string[] args)
        {
            try
            {
                string filePath = PathUtilities.GetInputFilePathOrDefault(args, "jwt.txt");
                string jwtToken = await File.ReadAllTextAsync(filePath);

                if (await ValidateJwtAsync(jwtToken))
                {
                    Console.WriteLine("✅ SUCCESS: JWT token passed all validation checks.");
                }
                else
                {
                    Console.WriteLine("❌ FAILURE: JWT token failed one or more validation checks.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🚨 EXCEPTION: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static async Task<bool> ValidateJwtAsync(string token)
        {
            bool result = true;
            try
            {
                var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token)
                               ?? throw new Exception("ERROR: JWT token is null.");

                string certificatesString = await JwtUtils.GetSigningCertificatesAsync(jwt);
                var selfSignedCerts = JwtUtils.RetrieveSelfSignedSigningCertificates(certificatesString);
                var selfSignedCert = selfSignedCerts[0];

                var extensionJson = Crypto.GetExtensionValueAsJObject(selfSignedCert, Constants.MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID);

                var vcekCertChainString = Crypto.GetReportValueDecodedString(extensionJson, "VcekCertChain");
                var endorsementsString = Crypto.GetReportValueDecodedString(extensionJson, "Endorsements");
                var snpReport = SnpAttestationReport.Parse(Crypto.GetReportValueDecodedBytes(extensionJson, "SnpReport"));

                result &= await ValidateTokenAsync(jwt, certificatesString);

                result &= ValidateTeeKind(selfSignedCert);
                // missing Report signing validation // Validate that the sevsnp report is signed by the leaf cert in the VCEK cert chain
                result &= ValidateVcekChainAgainstAmdRoots(vcekCertChainString);
                result &= VerifyLaunchMeasurement(endorsementsString, snpReport);
                result &= VerifyUvmEndorsementSignature(endorsementsString);
                result &= VerifyHostDataClaim(snpReport);
                result &= VerifyReportData(selfSignedCert, snpReport);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: JWT Validation Error, exception: " + ex.Message);
                return false;
            }
            return result;
        }

        /// <summary>
        /// Validates the signature and expiration of a JWT using the issuer's signing keys retrieved from its JWK endpoint.
        /// </summary>
        /// <param name="jwt">The JWT token to validate.</param>
        /// <returns>
        /// <c>true</c> if the token is valid and its signature is verified; otherwise, <c>false</c>.
        /// </returns>
        public static async Task<bool> ValidateTokenAsync(JwtSecurityToken jwt, string certificatesString)
        {
            try
            {
                var issuerPublicKeySet = new JsonWebKeySet(certificatesString);
                var parameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = issuerPublicKeySet.GetSigningKeys(),
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = true // Set to 'false' to skip expiration validation if the token is expired.
                };

                var handler = new JwtSecurityTokenHandler();
                var validationResult = await handler.ValidateTokenAsync(jwt.RawData, parameters);

                if (validationResult.IsValid)
                {
                    Console.WriteLine($"SUCCESS: Token is validated.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: JWT validation failed: {ex.Message}");
            }

            Console.WriteLine("ERROR: Failed to validate JWT.");
            return false;
        }

        /// <summary>
        /// Validates a JWT using a set of trusted RSA public keys.
        /// </summary>
        /// <remarks>
        /// This method performs standard JWT validation, including signature and expiration checks,
        /// using a set of trusted public keys (typically extracted from PEM-encoded certificates).
        /// The token is considered valid if it is successfully verified against any of the provided keys.
        /// </remarks>
        /// <param name="jwtToken">The JWT token to validate.</param>
        /// <param name="trustedKeys">A list of trusted RSA public keys used for validation.</param>
        /// <returns>
        /// <c>true</c> if the token is successfully validated by at least one trusted key; otherwise, <c>false</c>.
        /// </returns>
        private static async Task<bool> ValidateTokenWithTrustedKeysAsync(JwtSecurityToken jwtToken, List<RsaSecurityKey> trustedKeys)
        {
            var handler = new JwtSecurityTokenHandler();
            var isValid = false;
            var exceptions = new StringBuilder();

            foreach (var key in trustedKeys)
            {
                try
                {
                    var parameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = key,
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true
                    };

                    var validatedToken = await handler.ValidateTokenAsync(jwtToken.RawData, parameters);
                    isValid = validatedToken.IsValid;

                    Console.WriteLine($"SUCCESS: Token signature successfully validated using trusted key (KeyId: {key.KeyId ?? "<none>"}).");
                    break; // We can stop here
                }
                catch (SecurityTokenValidationException ex)
                {
                    exceptions.AppendLine($"WARNING: Signature validation failed with trusted key (KeyId: {key.KeyId ?? "<none>"}): {ex.Message}");
                }
                catch (Exception ex)
                {
                    exceptions.AppendLine($"WARNING: Unexpected error with trusted key (KeyId: {key.KeyId ?? "<none>"}): {ex.Message}");
                }
            }

            if (exceptions.Length > 0)
            {
                Console.WriteLine("Validation attempts summary:");
                Console.WriteLine(exceptions.ToString());
            }

            if (!isValid)
            {
                Console.WriteLine("ERROR: Failed to verify token signature with any of the trusted keys.");
            }

            return isValid;
        }

        /// <summary>
        /// Verifies whether the provided certificate contains valid attestation evidence for a SEV-SNP platform.
        /// This checks if the certificate includes the required TEE Kind extension and validates its value.
        /// </summary>
        /// <param name="certificate">The X.509 certificate to inspect for platform attestation evidence.</param>
        /// <returns>
        /// Returns <c>true</c> if the certificate contains valid SEV-SNP attestation evidence,
        /// including the required TEE Kind extension and expected platform identifier.
        /// Returns <c>false</c> if the extension is missing, the value is incorrect, or validation fails.
        /// </returns>
        private static bool ValidateTeeKind(X509Certificate2 certificate)
        {
            try
            {
                var teeKindValue = Crypto.GetExtensionValueAsUtf8StringByOid(certificate, Constants.MAA_EVIDENCE_TEEKIND_CERTIFICATE_OID);

                if (teeKindValue == null || teeKindValue != Constants.SevSnpTeeValue)
                {
                    Console.WriteLine($"ERROR: TEE Kind mismatch for certificate {certificate.Subject}. Expected '{Constants.SevSnpTeeValue}', got '{teeKindValue}'.");
                    return false;
                }

                Console.WriteLine("SUCCESS: Platform verified as ACI SEV-SNP.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Failed to read TEE Kind extension from certificate {certificate.Subject}: {ex.Message}");
            }
            return false;
        }

        /// <summary>
        /// Validates a VCEK certificate chain by building it and ensuring it is rooted in a trusted AMD root public key.
        /// </summary>
        /// <param name="vcekChainPemString">
        /// A PEM-encoded certificate chain string, where the first certificate is the VCEK (leaf),
        /// followed by any intermediate certificates, ending with the root certificate.
        /// </param>
        /// <returns>
        /// <c>true</c> if the certificate chain is valid and the root certificate's public key matches a known AMD root key; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method builds the certificate chain using <see cref="X509Chain"/> and validates it using
        /// a set of trusted AMD root public keys provided as PEM strings. Only the signature and chain integrity are checked;
        /// revocation is not validated.
        /// </remarks>
        private static bool ValidateVcekChainAgainstAmdRoots(string vcekChainPemString)
        {
            try
            {
                var trustedRoots = new[] { Crypto.PemStringToRsa(Constants.AmdProdRootKey), Crypto.PemStringToRsa(Constants.AmdProdRootKeyGenoa) };

                var certMatches = Regex.Matches(vcekChainPemString, "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOptions.Singleline);
                if (certMatches.Count < 1)
                {
                    Console.WriteLine("ERROR: Failed to validate vcek chain. No certificates found in the VCEK chain.");
                    return false;
                }

                // Convert PEMs to X509Certificate2 instances
                var certs = certMatches
                    .Select(certMatch => new X509Certificate2(Encoding.ASCII.GetBytes(certMatch.Value)))
                    .ToList();

                var leaf = certs[0];
                var intermediates = certs.Skip(1).ToList();

                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                foreach (var intermediate in intermediates)
                {
                    chain.ChainPolicy.ExtraStore.Add(intermediate);
                }

                bool isValidChain = chain.Build(leaf);
                if (!isValidChain)
                {
                    Console.WriteLine("ERROR: Failed to validate vcek chain. Chain build failed.");
                    return false;
                }

                var rootCertificate = chain.ChainElements[^1].Certificate;
                using var rootCertificateKey = rootCertificate.GetRSAPublicKey();
                if (rootCertificateKey == null)
                {
                    Console.WriteLine("ERROR: Failed to validate vcek chain. Could not extract public key from root certificate.");
                    return false;
                }

                foreach (var trustedKey in trustedRoots)
                {
                    if (Crypto.AreEqual(rootCertificateKey, trustedKey))
                    {
                        Console.WriteLine("SUCCESS: VCEK chain is valid and rooted in a trusted AMD key.");
                        return true;
                    }
                }

                Console.WriteLine("ERROR: Failed to validate vcek chain. Root certificate does not match any known AMD trusted public key.");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: Failed to validate VCEK chain: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Verifies that the hostdata value from a SEV-SNP attestation report matches the expected SHA-256 hash of the current CCE policy.
        /// </summary>
        /// <param name="snpReport">The parsed SEV-SNP attestation report.</param>
        /// <returns>
        /// <c>true</c> if the hostdata value in the SNP report matches the expected CCE policy hash; otherwise, <c>false</c>.
        /// </returns>
        private static bool VerifyHostDataClaim(SnpAttestationReport snpReport)
        {
            try
            {
                // Latest CCE policy as of 1.29.2025.
                // Hash was confirmed by computing the SHA256 of the CCE policy.
                // CCE policy was extracted from the ARM template & base64 decoded using Linux style line ending.
                const string expectedHostDataValue = "0178240eff4ef968efdcd735b8bcee63578c4eb9e4264178f747df149bf57bff";
                var hostDataValueSnpReport = snpReport.GetHostDataHex();
                if (!string.IsNullOrEmpty(hostDataValueSnpReport) && expectedHostDataValue.Equals(hostDataValueSnpReport))
                {
                    Console.WriteLine($"SUCCESS: Hostdata value '{hostDataValueSnpReport}' from SNP report matches expected policy hash '{expectedHostDataValue}'");
                    return true;
                }
                Console.WriteLine($"ERROR: Hostdata is missing or invalid. Found: {hostDataValueSnpReport ?? "<null>"}. Expected: {expectedHostDataValue}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Exception occurred while verifying hostdata: {ex.Message}");
            }

            return false;
        }

        /// <summary>
        /// Verifies that the launch measurement in the SEV-SNP attestation report matches the value endorsed in the UVM evidence.
        /// </summary>
        /// <param name="endorsementsString">A JSON string containing UVM endorsement data, including the encoded COSE Sign1 payload.</param>
        /// <param name="snpReport">The parsed SEV-SNP attestation report.</param>
        /// <returns>
        /// <c>true</c> if the launch measurement in the attestation report matches the endorsed value from the UVM evidence; otherwise, <c>false</c>.
        /// </returns>
        private static bool VerifyLaunchMeasurement(string endorsementsString, SnpAttestationReport snpReport)
        {
            try
            {
                var sign1Message = (Sign1Message)Message.DecodeFromBytes(GetUvmEndorsement(endorsementsString));
                var payloadJson = JObject.Parse(Encoding.UTF8.GetString(sign1Message.GetContent()));

                var endorsedLaunchMeasurement = payloadJson[Constants.SevSnpClaimNameLaunchMeasurement]?.ToString();
                var presentedLaunchMeasurement = snpReport.GetMeasurementHex();

                var result = string.Equals(endorsedLaunchMeasurement, presentedLaunchMeasurement, StringComparison.Ordinal);
                if (result)
                {
                    Console.WriteLine($"SUCCESS:  Uvm endorsement '{Constants.SevSnpClaimNameLaunchMeasurement}' value matches SEVSNP report value Launch measurement.");
                }
                else
                {
                    Console.WriteLine($"ERROR: Uvm endorsement '{Constants.SevSnpClaimNameLaunchMeasurement}' value does not match SEVSNP report value Launch measurement.");
                }
                Console.WriteLine($"                    SEVSNP report value launch measurement : {presentedLaunchMeasurement}");
                Console.WriteLine($"         Uvm endorsement '{Constants.SevSnpClaimNameLaunchMeasurement}' : {endorsedLaunchMeasurement}");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: Failed to verify launch measurement: " + ex.Message);
            }

            return false;
        }

        /// <summary>
        /// Verifies that SEVSNP.reportdata matches the SHA-256 hash of the signer's public key.
        /// This confirms that the attestation is bound to the holder of the corresponding private key.
        /// </summary>
        /// <param name="cert">The certificate containing the RSA public key.</param>
        /// <param name="snpReport">The SEV-SNP attestation report.</param>
        /// <returns>True if the reportdata matches the expected public key hash; otherwise, false.</returns>
        private static bool VerifyReportData(X509Certificate2 cert, SnpAttestationReport snpReport)
        {
            try
            {
                string expectedHashHex = Crypto.HashPemWithNullTerminator(cert);
                string reportDataHex = snpReport.GetReportDataHex();
                byte[] reportDataBytes = Convert.FromHexString(reportDataHex);

                if (reportDataBytes.Length != 64)
                {
                    Console.WriteLine("ERROR: Invalid ReportData length. Expected 64 bytes.");
                    return false;
                }

                if (!reportDataBytes.Skip(32).All(b => b == 0x00))
                {
                    Console.WriteLine("ERROR: Upper 32 bytes of ReportData (bytes 32–63) must be zero.");
                    return false;
                }

                string actualHashHex = Convert.ToHexString(reportDataBytes.Take(32).ToArray()).ToLowerInvariant();
                if (!actualHashHex.Equals(expectedHashHex, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("ERROR: Lower 32 bytes of ReportData do not match the expected public key hash.");
                    Console.WriteLine($"Expected: {expectedHashHex}");
                    Console.WriteLine($"Actual:   {actualHashHex}");
                    return false;
                }

                Console.WriteLine("SUCCESS: SEVSNP.reportdata matches hash of expected public key.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Exception while verifying ReportData: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Verifies that the UVM endorsement signature chains up to a trusted AMD Certificate Authority (C-ACI).
        /// This confirms the authenticity of the UVM endorsement by validating its signing certificate
        /// against a known set of AMD-issued trust anchors.
        /// </summary>
        /// <param name="endorsementsString">A JSON string containing the encoded UVM endorsement.</param>
        /// <returns>True if the endorsement signature is valid and chains to a trusted AMD C-ACI root; otherwise, false.</returns>
        private static bool VerifyUvmEndorsementSignature(string endorsementsString)
        {
            try
            {
                var coseSign1Bytes = GetUvmEndorsement(endorsementsString);
                var certificates = Crypto.ExtractX509CertificatesFromBytes(coseSign1Bytes);

                var trustAnchors = new[]
                {
                    Crypto.PemStringToRsa(Constants.UvmEndorsementSigningKeyPrssCA),
                    Crypto.PemStringToRsa(Constants.UvmEndorsementSigningKeyPrssJan2023)
                };

                if (Crypto.BuildAndValidateCertChain(certificates, trustAnchors, Crypto.CertValidationTarget.Root))
                {
                    // TODO OLGA: check on this. The chain is supposed to be validated for the leaf cert, but it passes for the root 
                    Console.WriteLine("SUCCESS: UVM Endorsement signature successfully verified against trusted C-ACI root.");
                    return true;

                }
                Console.WriteLine("ERROR: UVM Endorsement signature failed: no trusted root matched.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: Failed to verify UVM endorsement signature: " + ex);
            }

            return false;
        }

        private static byte[] GetUvmEndorsement(string endorsementsString)
        {
            var endorsementsJson = JObject.Parse(endorsementsString);
            var uvmArray = endorsementsJson["Uvm"] as JArray;
            if (uvmArray == null || uvmArray.Count != 1)
            {
                throw new Exception("Invalid 'Uvm' array in endorsements.");
            }

            // Uvm endorsement is expected to be a base64url for a COSE Sign1 document.
            var rawEndorsement = uvmArray[0].ToString();
            var endorsementBytes = Base64UrlEncoder.DecodeBytes(rawEndorsement);
            return endorsementBytes;
        }
    } // Program
}