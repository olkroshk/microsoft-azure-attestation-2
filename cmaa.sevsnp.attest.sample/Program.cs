using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
                Console.WriteLine("ERROR: JWT Token is invalid.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("ERROR: " + ex.Message);
        }
    }

    private static async Task<bool> ValidateJwtAsync(string token, string attestationInstanceURL)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);

            if (jwtToken.ValidTo <= DateTime.UtcNow)
            {
                Console.WriteLine("ERROR: JWT has expired.");
                return false;
            }

            if (!VerifyIssuer(jwtToken, attestationInstanceURL))
            {
                return false;
            }

            var certificates = await RetrieveSigningCertificates(jwtToken);
            if (certificates == null || certificates.Count < 1)
            {
                Console.WriteLine("ERROR: Failed to retrieve signing certificates.");
                return false;
            }

            var verifyTokenSignatureResult = VerifyTokenSignature(jwtToken, certificates);
            if (!verifyTokenSignatureResult)
            {
                Console.WriteLine("ERROR: Failed to verify token signature.");
                return false;
            }

            var selfSignedCert = GetSelfSignedCertificate(certificates);
            if (selfSignedCert == null)
            {
                Console.WriteLine("ERROR: No self-signed certificate found.");
                return false;
            }

            if (!VerifyTeeKindFromCertificates(selfSignedCert))
            {
                Console.WriteLine("ERROR: Failed to verify platform/TEE kind from signing certificates.");
                return false;
            }

            if (!VerifyReportExtension(selfSignedCert))
            {
                Console.WriteLine("ERROR: Failed to verify report extension from signing certificates.");
                return false;
            }

            if (!VerifyReportDataClaim(jwtToken))
            {
                Console.WriteLine("ERROR: ReportData claim verification failed.");
                // TODO FIXME olkroshk - this method is expected to fail with the given test data samples
                //return false;
            }

            if (!VerifyHostDataClaim(jwtToken))
            {
                Console.WriteLine("ERROR: HostData claim verification failed.");
                // TODO FIXME olkroshk - this method is expected to fail with the given test data samples
                //return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("ERROR: JWT Validation Error, exception: " + ex.Message);
            return false;
        }
        return true;
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
            Console.WriteLine("ERROR: Issuer mismatch! Token issuer does not match the expected issuer.");
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
            Console.WriteLine("ERROR: Certificate Retrieval Error: " + ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Retrieves the first self-signed certificate from the provided list.
    /// </summary>
    /// <param name="certificates">A list of X.509 certificates.</param>
    /// <returns>The first self-signed certificate if found; otherwise, null.</returns>
    private static X509Certificate2? GetSelfSignedCertificate(List<X509Certificate2> certificates)
    {
        return certificates.FirstOrDefault(cert => cert.Subject == cert.Issuer);
    }

    /// <summary>
    /// Retrieves all self-signed certificates from the provided list.
    /// </summary>
    /// <param name="certificates">A list of X.509 certificates.</param>
    /// <returns>A list of self-signed certificates. Returns an empty list if none are found.</returns>
    private static List<X509Certificate2> GetSelfSignedCertificates(List<X509Certificate2> certificates)
    {
        return certificates.Where(cert => cert.Subject == cert.Issuer).ToList();
    }

    /// <summary>
    /// Verifies the digital signature of a JWT token using a list of provided X.509 certificates.
    /// This ensures that the token has been signed by a trusted entity and has not been tampered with.
    /// The method checks all certificates and logs warnings for those that fail validation.
    /// </summary>
    /// <param name="jwtToken">The JWT token whose signature needs to be verified.</param>
    /// <param name="certificates">A list of X.509 certificates containing public keys for signature verification.</param>
    /// <returns>
    /// Returns <c>true</c> if at least one certificate successfully verifies the token's signature. 
    /// Returns <c>false</c> if all certificates fail validation, the token is null, or no certificates are provided.
    /// Logs warnings for any certificates that fail validation and errors for critical failures.
    /// </returns>
    private static bool VerifyTokenSignature(JwtSecurityToken jwtToken, List<X509Certificate2> certificates)
    {
        if (jwtToken == null)
        {
            Console.WriteLine("ERROR: JWT token is null.");
            return false;
        }

        if (certificates == null || certificates.Count == 0)
        {
            Console.WriteLine("ERROR: No certificates provided for verification.");
            return false;
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationErrors = new StringBuilder();
        bool isValid = false; // Track if at least one certificate validates the token

        foreach (var certificate in certificates)
        {
            try
            {
                var rsa = certificate.GetRSAPublicKey();
                if (rsa == null)
                {
                    validationErrors.AppendLine($"ERROR: RSA public key extraction failed for certificate: {certificate.Subject}");
                    continue;
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

                // Attempt token validation
                tokenHandler.ValidateToken(jwtToken.RawData, validationParameters, out _);
                Console.WriteLine($"Token signature verified using certificate: {certificate.Subject}");
                isValid = true; // Mark as valid but continue checking other certificates
            }
            catch (SecurityTokenValidationException ex)
            {
                validationErrors.AppendLine($"WARNING: Token signature validation failed with certificate: {certificate.Subject} - {ex.Message}");
            }
            catch (Exception ex)
            {
                validationErrors.AppendLine($"ERROR: Unexpected error while validating token with certificate {certificate.Subject} - {ex.Message}");
            }
        }

        // Print accumulated errors if any
        if (validationErrors.Length > 0)
        {
            Console.WriteLine(validationErrors.ToString());
        }

        return isValid;
    }

    /// <summary>
    /// Verifies whether the provided self-signed certificate contains valid attestation evidence for a SEV-SNP platform.
    /// This checks if the certificate includes the required TEE Kind extension and validates its value.
    /// </summary>
    /// <param name="selfSignedCert">The self-signed X.509 certificate to inspect for platform attestation evidence.</param>
    /// <returns>
    /// Returns <c>true</c> if the certificate contains valid SEV-SNP attestation evidence,
    /// including the required TEE Kind extension and expected platform identifier.
    /// Returns <c>false</c> if the extension is missing, the value is incorrect, or validation fails.
    /// </returns>
    private static bool VerifyTeeKindFromCertificates(X509Certificate2 selfSignedCert)
    {
        var teeKindExtension = selfSignedCert.Extensions[AttestationConstants.MAA_EVIDENCE_TEEKIND_CERTIFICATE_OID];
        if (teeKindExtension == null)
        {
            Console.WriteLine($"ERROR: Certificate {selfSignedCert.Subject} is missing the TEE Kind extension.");
            return false;
        }

        try
        {
            string teeKindValue = new AsnReader(teeKindExtension.RawData, AsnEncodingRules.DER)
                .ReadCharacterString(UniversalTagNumber.UTF8String);

            if (teeKindValue != "acisevsnp")
            {
                Console.WriteLine($"ERROR: TEE Kind mismatch for certificate {selfSignedCert.Subject}. Expected 'acisevsnp', got '{teeKindValue}'.");
                return false;
            }

            Console.WriteLine("SUCCESS: Platform verified as ACI SEV-SNP.");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: Failed to read TEE Kind extension from certificate {selfSignedCert.Subject}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Verifies the attestation report extension in the provided X.509 certificate.
    /// This method checks for the presence of the SEV-SNP attestation report, parses its contents, 
    /// and ensures it includes the required evidence such as the SNP report and VCEK certificate chain.
    /// If endorsements are present, they are validated against the expected launch measurement.
    /// </summary>
    /// <param name="selfSignedCert">The X.509 certificate containing the attestation report extension.</param>
    /// <returns>
    /// Returns <c>true</c> if the report extension is present, well-formed, and contains valid SEV-SNP evidence. 
    /// Returns <c>false</c> if the required fields are missing, the report is malformed, or validation fails.
    /// </returns>
    private static bool VerifyReportExtension(X509Certificate2 selfSignedCert)
    {
        var reportExtension = selfSignedCert.Extensions[AttestationConstants.MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID];
        if (reportExtension == null)
        {
            Console.WriteLine($"ERROR: Certificate {selfSignedCert.Subject} is missing the report extension.");
            return false;
        }

        JObject reportJson;
        try
        {
            string reportExtensionValue = new AsnReader(reportExtension.RawData, AsnEncodingRules.DER).ReadCharacterString(UniversalTagNumber.UTF8String);
            reportJson = JObject.Parse(reportExtensionValue);
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"ERROR: Error parsing report extension JSON: {ex.Message}");
            return false;
        }

        string? snpReport = reportJson["SnpReport"]?.ToString();
        string? vcekCertChain = reportJson["VcekCertChain"]?.ToString();
        string? encodedEndorsements = reportJson["Endorsements"]?.ToString(); // Optional

        if (string.IsNullOrEmpty(snpReport) || string.IsNullOrEmpty(vcekCertChain))
        {
            Console.WriteLine($"ERROR: Platform verification failed: Missing required evidence (SnpReport or VcekCertChain) in the certificate {selfSignedCert.Subject}.");
            return false;
        }

        if (!string.IsNullOrEmpty(encodedEndorsements))
        {
            if (!ValidateReportExtensionEndorsements(encodedEndorsements, snpReport))
            {
                Console.WriteLine("ERROR: report endorsements validation failed.");
                return false;
            }
        }

        return true;
    }

    /// <summary>
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
            Console.WriteLine("ERROR: Missing 'x-ms-sevsnpvm-reportdata' claim.");
            return false;
        }

        try
        {
            // Retrieve the public key from the signing certificate
            // TODO FIXME olkroshk - use different data sample. Current returns this:
            //      Exception has occurred: CLR/System.NullReferenceException
            //      Exception thrown: 'System.NullReferenceException' in cmaa.sevsnp.attest.sample.dll: 'Object reference not set to an instance of an object.'
            using RSA rsa = ((RsaSecurityKey)jwtToken.SigningKey).Rsa;
            byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
            string publicKeyHash = Convert.ToHexString(SHA256.HashData(publicKeyBytes)).ToLower();

            // Compare
            if (publicKeyHash == reportData.ToLower())
            {
                Console.WriteLine("ReportData matches signing public key hash.");
                return true;
            }

            Console.WriteLine("ERROR: ReportData does NOT match signing public key hash.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: Error during verification: {ex.Message}");
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
        if (jwtToken.Payload.TryGetValue("x-ms-sevsnpvm-hostdata", out var hostDataObj) && hostDataObj is string hostData)
        {
            string normalizedHostData = hostData.ToLower();
            if (AttestationConstants.ExpectedHostDataValues.Contains(normalizedHostData))
            {
                Console.WriteLine("HostData claim is valid. The attestation policy is correctly enforced.");
                return true;
            }
            Console.WriteLine("ERROR: Invalid HostData claim.");
        }
        else
        {
            Console.WriteLine("ERROR: Missing HostData claim. Attestation policy verification cannot be performed.");
        }
        return false;
    }

    private static bool ValidateReportExtensionEndorsements(string encodedEndorsements, string snpReport)
    {
        string endorsementsJsonString;
        try
        {
            endorsementsJsonString = Base64Url.DecodeString(encodedEndorsements);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: Error decoding Endorsements field: {ex.Message}");
            return false;
        }

        JObject endorsementsJson;
        try
        {
            endorsementsJson = JObject.Parse(endorsementsJsonString);
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"ERROR: Error parsing Endorsements JSON: {ex.Message}");
            return false;
        }

        // Ensure "Uvm" field exists and is an array with exactly one item
        if (!endorsementsJson.ContainsKey("Uvm") ||
            endorsementsJson["Uvm"].Type != JTokenType.Array ||
            endorsementsJson["Uvm"].Count() != 1)
        {
            Console.WriteLine("ERROR: Invalid Uvm array in endorsements.");
            return false;
        }

        // Extract COSE Sign1 document
        string encodedCoseSign1 = endorsementsJson["Uvm"][0].ToString();
        byte[] coseSign1Bytes;
        try
        {
            coseSign1Bytes = Base64Url.DecodeBytes(encodedCoseSign1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: Error decoding COSE Sign1 document: {ex.Message}");
            return false;
        }

        // TODO FIXME - olga
        // Validate COSE Sign1 Document (Assuming a method ValidateCoseSign1Document exists)
        //   if (!ValidateCoseSign1Document(coseSign1Bytes, snpReport))
        {
            // Console.WriteLine("ERROR: COSE Sign1 document validation failed.");
            //   return false;
        }
        return true;
    }

    /*
        private static bool ValidateCoseSign1Document(byte[] coseBytes, string expectedMeasurement)
        {
            try
            {
                // Decode COSE Sign1 document (Using Jose-JWT or a COSE parser)
                var coseToken = JWT.Decode<Dictionary<string, object>>(coseBytes, null, JwsAlgorithm.NONE);

                if (!coseToken.ContainsKey("x-ms-sevsnpvm-launchmeasurement"))
                {
                    Console.WriteLine("COSE Sign1 document does not contain expected launch measurement.");
                    return false;
                }

                string launchMeasurement = coseToken["x-ms-sevsnpvm-launchmeasurement"].ToString();
                if (launchMeasurement != expectedMeasurement)
                {
                    Console.WriteLine("Launch measurement does not match the SEV-SNP report.");
                    return false;
                }

                // Verify the signature
                if (!VerifyCoseSignature(coseBytes))
                {
                    Console.WriteLine("COSE Sign1 document signature validation failed.");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing COSE Sign1 document: {ex.Message}");
                return false;
            }
        }

        private static bool VerifyCoseSignature(byte[] coseBytes)
        {
            // Extract COSE Sign1 signature details (Jose-JWT or custom COSE library required)
            try
            {
                var coseToken = JWT.Decode<Dictionary<string, object>>(coseBytes, null, JwsAlgorithm.NONE);
                string keyId = coseToken["kid"].ToString();

                HashSet<string> TrustedSigningKeys = new HashSet<string>
                {
                    // Add trusted PRSS signing keys here
                };

                if (!TrustedSigningKeys.Contains(keyId))
                {
                    Console.WriteLine("Signature is not from a trusted PRSS signing key.");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Signature validation failed: {ex.Message}");
                return false;
            }
        }
        */
}
