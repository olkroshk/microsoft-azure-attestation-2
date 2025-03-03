using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

public class AttestationClient
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private const string ApiVersion = "2022-08-01";

    public AttestationClient(string baseUrl, HttpClient httpClient = null)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<AttestationResponse> AttestSevSnpVmAsync(AttestSevSnpVmRequest request)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var url = $"{_baseUrl}/attest/SevSnpVm?api-version={ApiVersion}";
        var requestBody = JsonConvert.SerializeObject(request);
        var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

        HttpResponseMessage response = await _httpClient.PostAsync(url, content);

        string responseContent = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Error {response.StatusCode}: {responseContent}");
        }

        return JsonConvert.DeserializeObject<AttestationResponse>(responseContent);
    }
}

public class AttestSevSnpVmRequest
{
    [JsonProperty("report")]
    public required string Report { get; set; }

    [JsonProperty("runtimeData")]
    public RuntimeData RuntimeData { get; set; }

    [JsonProperty("initTimeData")]
    public InitTimeData InitTimeData { get; set; }

    [JsonProperty("draftPolicyForAttestation")]
    public string DraftPolicyForAttestation { get; set; }

    [JsonProperty("nonce")]
    public string Nonce { get; set; }
}

public class RuntimeData
{
    [JsonProperty("data")]
    public required string Data { get; set; }

    [JsonProperty("dataType")]
    public required string DataType { get; set; }
}

public class InitTimeData
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

// Cross-Platform Example Usage
public class Program
{
    public static async Task Main(string[] args)
    {
        try
        {
            var client = new AttestationClient("https://instance.attest.azure.net");
            var request = new AttestSevSnpVmRequest
            {
                Report = "Base64EncodedReport",
                RuntimeData = new RuntimeData
                {
                    Data = "Base64EncodedRuntimeData",
                    DataType = "JSON"
                },
                Nonce = "randomNonce"
            };

            var response = await client.AttestSevSnpVmAsync(request);

            Console.WriteLine("Attestation Token: " + response.Token);
            
            // TODO: Olga, perform validation steps here
            Console.WriteLine("Validation steps to be implemented...");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
