using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
public class Program
{
    private const string ReportSample = AttestationConstants.ReportSample;
    private const string RuntimeDataSample = AttestationConstants.RuntimeDataSample;
    private const string InitTimeDataSample = AttestationConstants.InitTimeDataSample;

    public static async Task Main(string[] args)
    {
        try
        {
            var attestationInstanceURL = AttestationConstants.AttestationInstanceURL;
            var client = new AttestationClient(attestationInstanceURL);
            var request = new AttestSevSnpVmRequest
            {
                Report = ReportSample,
                RuntimeData = new RuntimeData
                {
                    Data = RuntimeDataSample,
                    DataType = "JSON"
                },
            };

            var response = await client.AttestSevSnpVmAsync(request);
            Console.WriteLine("Attestation Token: " + response.Token);

            if (await ValidateJwtAsync(response.Token, attestationInstanceURL))
            {
                Console.WriteLine("JWT Token is valid.");
            }
            else
            {
                Console.WriteLine("JWT Token is invalid.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }

    private static async Task<bool> ValidateJwtAsync(string token, string attestationInstanceURL)
    {
        // TODO: this is needed to temporary ignore the results. 
        bool validationSucceeded = true;

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);

            if (jwtToken.ValidTo <= DateTime.UtcNow)
            {
                Console.WriteLine(">>> JWT has expired.");
                //return false;
                validationSucceeded = false;
            }
            
            if (!VerifyIssuer(jwtToken, attestationInstanceURL))
            {
                //return false;
                validationSucceeded = false;
            }

            var certificates = await RetrieveSigningCertificates(jwtToken);
            if (certificates == null || certificates.Count < 1)
            {
                Console.WriteLine(">>> Failed to retrieve signing certificates.");
                return false;
            }

            // Verification Step: Verify Token Signature
            
            //var verifyTokenSignatureManuallyResult = VerifyTokenSignatureManually(jwtToken, certificates[0]);
            //if (!verifyTokenSignatureManuallyResult || !verifyTokenSignatureResult)
            var verifyTokenSignatureResult = VerifyTokenSignature(jwtToken, certificates[0]);
            if (!verifyTokenSignatureResult)
            {
                Console.WriteLine(">>> Failed to verify token signature.");
                //return false;
                validationSucceeded = false;
            }

            if (!VerifyPlatformFromCertificates(certificates))
            {
                Console.WriteLine(">>> Failed to verify platform from signing certificates.");
                //return false;
                validationSucceeded = false;
            }

            if (!VerifyReportDataClaim(jwtToken))
            {
                Console.WriteLine(">>> ReportData claim verification failed.");
                //return false;
                validationSucceeded = false;
            }

            if (!VerifyHostDataClaim(jwtToken))
            {
                Console.WriteLine(">>> HostData claim verification failed.");
                //return false;
                validationSucceeded = false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(">>> JWT Validation Error: " + ex.Message);
            //return false;
            validationSucceeded = false;
        }
        return validationSucceeded;
    }

    /// <summary>
    /// Verifies that the issuer of the JWT token matches the expected issuer.
    /// This ensures that the token originates from a trusted source.
    /// </summary>
    /// <param name="jwtToken">The JWT token whose issuer needs to be verified.</param>
    /// <param name="expectedIssuer">The expected issuer value that the token should match.</param>
    /// <returns>
    /// Returns <c>true</c> if the token's issuer matches the expected issuer.
    /// Returns <c>false</c> if the issuer does not match.
    /// </returns>
    private static bool VerifyIssuer(JwtSecurityToken jwtToken, string expectedIssuer)
    {
        string? issuer = jwtToken.Issuer;
        Console.WriteLine("JWT Issuer: " + issuer);
        if (issuer != expectedIssuer)
        {
            Console.WriteLine(">>> Issuer mismatch! Token issuer does not match the expected issuer.");
            return false;
        }
        return true;
    }

    private static async Task<List<X509Certificate2>?> RetrieveSigningCertificates(JwtSecurityToken jwtToken)
    {
        if (jwtToken.Header.TryGetValue("jku", out var jkuObject) && jkuObject is string jku)
        {
            Console.WriteLine("JWT Signing Certificates Endpoint (jku): " + jku);
            return await RetrieveCertificatesFromJku(jku);
        }
        return null;
    }

    private static async Task<List<X509Certificate2>?> RetrieveCertificatesFromJku(string jkuUrl)
    {
        try
        {
            using HttpClient httpClient = new();
            string certResponse = await httpClient.GetStringAsync(jkuUrl);
            //Console.WriteLine("Raw response from " + jkuUrl);
            //Console.WriteLine(certResponse);

            var jsonResponse = JsonConvert.DeserializeObject<dynamic>(certResponse);

            List<X509Certificate2> certificates = new();
            if (jsonResponse?.keys != null)
            {
                foreach (var key in jsonResponse.keys)
                {
                    var certBase64 = key?.x5c[0]?.ToString();
                    if (!string.IsNullOrEmpty(certBase64))
                    {
                        var certBytes = Convert.FromBase64String(certBase64);
                        certificates.Add(new X509Certificate2(certBytes));
                    }
                }
            }
            return certificates.Count > 0 ? certificates : null;
        }
        catch (Exception ex)
        {
            Console.WriteLine(">>> Certificate Retrieval Error: " + ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Verifies the digital signature of a JWT token using the provided X.509 certificate.
    /// This ensures that the token has been signed by a trusted entity and has not been tampered with.
    /// </summary>
    /// <param name="jwtToken">The JWT token whose signature needs to be verified.</param>
    /// <param name="certificate">The X.509 certificate containing the public key used for signature verification.</param>
    /// <returns>
    /// Returns <c>true</c> if the token's signature is valid and was signed by the expected issuer. 
    /// Returns <c>false</c> if the signature verification fails, the certificate's public key cannot be extracted, 
    /// or an exception occurs during validation.
    /// </returns>
    private static bool VerifyTokenSignature(JwtSecurityToken jwtToken, X509Certificate2 certificate)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var rsa = certificate.GetRSAPublicKey();
            if (rsa == null)
            {
                Console.WriteLine(">>> RSA public key extraction failed from certificate: " + certificate.Subject);
                return false;
            }

            // Normalize certificate issuer to match JWT Issuer
            string normalizedCertIssuer = certificate.Issuer.Replace("CN=", "").Trim();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                ValidateIssuer = true,
                ValidIssuer = normalizedCertIssuer,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            tokenHandler.ValidateToken(jwtToken.RawData, validationParameters, out _);
            Console.WriteLine("VerifyTokenSignature - Token signature is valid.");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine(">>> Token signature validation failed: " + ex.Message);
            return false;
        }
    }

    private static bool VerifyTokenSignatureManually(JwtSecurityToken jwtToken, X509Certificate2 certificate)
    {
        try
        {
            var rsa = certificate.GetRSAPublicKey();
            if (rsa == null)
            {
                Console.WriteLine(">>> RSA public key extraction failed from certificate: " + certificate.Subject);
                return false;
            }

            // Extract signature and signed data
            var encodedHeaderPayload = jwtToken.EncodedHeader + "." + jwtToken.EncodedPayload;
            var signatureBytes = Base64Url.DecodeBytes(jwtToken.RawSignature);
            var dataBytes = Encoding.UTF8.GetBytes(encodedHeaderPayload);

            // Verify the signature manually
            bool isValid = rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!isValid)
            {
                Console.WriteLine(">>> Token signature verification failed.");
                return false;
            }

            // Normalize certificate issuer to match JWT Issuer
            string normalizedCertIssuer = certificate.Issuer.Replace("CN=", "").Trim();

            // Manual check to compare the Issuer
            if (jwtToken.Issuer != normalizedCertIssuer)
            {
                Console.WriteLine($">>> Issuer mismatch: Token Issuer '{jwtToken.Issuer}' does not match Cert Issuer '{normalizedCertIssuer}'");
                return false;
            }

            Console.WriteLine("VerifyTokenSignatureManually - Token signature is valid.");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine(">>> Token signature validation failed: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Verifies whether the provided certificates contain valid attestation evidence for a SEV-SNP platform.
    /// This checks if the certificate includes specific Azure Attestation extensions and validates their contents.
    /// </summary>
    /// <param name="certificates">A list of X.509 certificates to inspect for platform attestation evidence.</param>
    /// <returns>
    /// Returns <c>true</c> if a certificate is found that contains valid SEV-SNP attestation evidence,
    /// including the required TEE Kind extension and expected platform identifier.
    /// Returns <c>false</c> if no valid evidence is found or verification fails.
    /// </returns>
    private static bool VerifyPlatformFromCertificates(List<X509Certificate2> certificates)
    {
        const string MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID = "1.3.6.1.4.1.311.105.1000.1";
        const string MAA_EVIDENCE_TEEKIND_CERTIFICATE_OID = "1.3.6.1.4.1.311.105.1000.2";
        try
        {
            foreach (var cert in certificates)
            {
                bool isSelfSigned = cert.Subject == cert.Issuer;
                if (isSelfSigned)
                {
                    var reportExtension = cert.Extensions[MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID];
                    if (reportExtension == null)
                    {
                        Console.WriteLine("Platform verification failed: Missing report extension.");
                        return false;
                    }
                    AsnReader reportReader = new AsnReader(reportExtension.RawData, AsnEncodingRules.DER);
                    string reportExtensionValue = reportReader.ReadCharacterString(UniversalTagNumber.UTF8String);
                    dynamic reportJson = JsonConvert.DeserializeObject(reportExtensionValue);
                    if (reportJson?["SnpReport"] == null || reportJson?["VcekCertChain"] == null || reportJson?["Endorsements"] == null)
                    {
                        Console.WriteLine("Platform verification failed: Missing required evidence in the certificate.");
                        return false;
                    }

                    var teeKindExtension = cert.Extensions[MAA_EVIDENCE_TEEKIND_CERTIFICATE_OID];
                    if (teeKindExtension == null)
                    {
                        Console.WriteLine("Platform verification failed: Missing TEE Kind extension.");
                        return false;
                    }
                    AsnReader teeKindReader = new AsnReader(teeKindExtension.RawData, AsnEncodingRules.DER);
                    string teeKindValue = teeKindReader.ReadCharacterString(UniversalTagNumber.UTF8String);
                    if (teeKindValue != "acisevsnp")
                    {
                        Console.WriteLine("Platform verification failed: TEE Kind mismatch.");
                        return false;
                    }

                    Console.WriteLine("Platform verified as ACI SEV-SNP.");
                    return true;
                }
            }
            Console.WriteLine(">>> No valid certificate found.");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine(">>> Platform verification error: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// TODO FIXME
    /// Verifies if hash of the public key that signed the attestation token matches the report data field.
    /// Extracts the public key from the attestation token's signing certificate,
    /// computes its SHA-256 hash, and verifies that it matches the value 
    /// in the 'x-ms-sevsnpvm-reportdata' claim.
    /// This ensures that the attestation token was signed by the expected key 
    /// and maintains the integrity of the attestation process.
    /// </summary>
    /// <param name="jwtToken">The JWT token containing attestation claims and the signing certificate.</param>
    /// <returns>
    /// Returns <c>true</c> if the computed SHA-256 hash of the signing public key 
    /// matches the 'x-ms-sevsnpvm-reportdata' claim. Returns <c>false</c> if the claim is missing, 
    /// the public key cannot be retrieved, or the hash does not match.
    /// </returns>
    private static bool VerifyReportDataClaim(JwtSecurityToken jwtToken)
    {
        // Extract 'x-ms-sevsnpvm-reportdata' from JWT payload
        if (!jwtToken.Payload.TryGetValue("x-ms-sevsnpvm-reportdata", out var reportDataObj) || reportDataObj is not string reportData)
        {
            Console.WriteLine(">>> Missing 'x-ms-sevsnpvm-reportdata' claim.");
            return false;
        }

        try
        {
            // Retrieve the public key from the signing certificate
            using RSA rsa = ((RsaSecurityKey)jwtToken.SigningKey).Rsa;
            byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
            string publicKeyHash = Convert.ToHexString(SHA256.HashData(publicKeyBytes)).ToLower();

            // Compare
            if (publicKeyHash == reportData.ToLower())
            {
                Console.WriteLine("ReportData matches signing public key hash.");
                return true;
            }

            Console.WriteLine(">>> ReportData does NOT match signing public key hash.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($">>> Error during verification: {ex.Message}");
        }

        return false;
    }

    /// <summary>
    /// Validates the 'x-ms-sevsnpvm-hostdata' claim in the attestation token.
    /// Ensures that the attestation report belongs to Azure Attestation and that the expected policy is enforced.
    /// For SEV-SNP, this checks if the provided HOST_DATA matches an allowed set of policy hashes.
    /// </summary>
    /// <param name="jwtToken">The JWT token containing the attestation claims.</param>
    /// <returns>True if the claim is valid and matches an expected policy, otherwise false.</returns>
    private static bool VerifyHostDataClaim(JwtSecurityToken jwtToken)
    {
        var expectedValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Known valid CCE policy hash
            "ADD-ME"
        };

        if (jwtToken.Payload.TryGetValue("x-ms-sevsnpvm-hostdata", out var hostDataObj) && hostDataObj is string hostData)
        {
            // Normalize case for comparison
            string normalizedHostData = hostData.ToLower();

            // Validate against expected policy hashes
            if (expectedValues.Contains(normalizedHostData))
            {
                Console.WriteLine("HostData claim is valid. The attestation policy is correctly enforced.");
                return true;
            }
            Console.WriteLine(">>> Invalid HostData claim.");
        }
        else
        {
            Console.WriteLine(">>> Missing HostData claim. Attestation policy verification cannot be performed.");
        }
        return false;
    }
}
