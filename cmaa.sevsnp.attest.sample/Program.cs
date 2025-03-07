using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Newtonsoft.Json;

public class AttestationClient(string baseUrl)
{
    private readonly HttpClient _httpClient = new HttpClient();
    private readonly string _baseUrl = baseUrl.TrimEnd('/');
    private const string ApiVersion = "2022-08-01";

    public async Task<AttestationResponse> AttestSevSnpVmAsync(AttestSevSnpVmRequest request)
    {
        if (request != null)
        {
            var url = $"{_baseUrl}/attest/SevSnpVm?api-version={ApiVersion}";
            var requestBody = JsonConvert.SerializeObject(request);
            var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await _httpClient.PostAsync(url, content);
            string responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Error {response.StatusCode}: {responseContent}");
            }

            return JsonConvert.DeserializeObject<AttestationResponse>(responseContent) ?? throw new InvalidOperationException("Failed to deserialize AttestationResponse");
        }

        throw new ArgumentNullException(nameof(request));
    }
}

public class AttestSevSnpVmRequest
{
    [JsonProperty("report")]
    public string Report { get; set; } = "DefaultBase64EncodedReport";

    [JsonProperty("runtimeData")]
    public RuntimeData RuntimeData { get; set; } = new RuntimeData
    {
        Data = "Base64EncodedRuntimeData",
        DataType = "JSON"
    };

    [JsonProperty("nonce")]
    public string Nonce { get; set; } = "randomNonce";
}

public class RuntimeData
{
    [JsonProperty("data")]
    public required string Data { get; set; }

    [JsonProperty("dataType")]
    public required string DataType { get; set; }
}

public class AttestationResponse
{
    [JsonProperty("token")]
    public required string Token { get; set; }
}

public class Program
{
    public static async Task Main(string[] args)
    {
        try
        {
            string report = args.Length > 0 ? args[0] : "DefaultBase64EncodedReport";
            var client = new AttestationClient("https://sharedneu.neu.test.attest.azure.net");
            var request = new AttestSevSnpVmRequest { Report = report };

            var response = await client.AttestSevSnpVmAsync(request);
            Console.WriteLine("Attestation Token: " + response.Token);
            
            if (ValidateJwt(response.Token))
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

    private static bool ValidateJwt(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            
            Console.WriteLine("JWT Issuer: " + jwtToken.Issuer);
            Console.WriteLine("JWT Subject: " + jwtToken.Subject);
            Console.WriteLine("JWT Expiration: " + jwtToken.ValidTo);
            
            return jwtToken.ValidTo > DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            Console.WriteLine("JWT Validation Error: " + ex.Message);
            return false;
        }
    }
}
