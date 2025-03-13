using Newtonsoft.Json;
using System.Text;

public class AttestationClient
{
    private readonly HttpClient _httpClient = new();
    private readonly string _baseUrl;
    private const string ApiVersion = "2022-08-01";

    public AttestationClient(string baseUrl)
    {
        _baseUrl = baseUrl.TrimEnd('/');
    }

    public async Task<AttestationResponse> AttestSevSnpVmAsync(AttestSevSnpVmRequest request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var url = $"{_baseUrl}/attest/SevSnpVm?api-version={ApiVersion}";
        var requestBody = JsonConvert.SerializeObject(request);
        var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

        HttpResponseMessage response = await _httpClient.PostAsync(url, content);
        string responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Error {response.StatusCode}: {responseContent}");
        }

        return JsonConvert.DeserializeObject<AttestationResponse>(responseContent) ?? 
               throw new InvalidOperationException("Failed to deserialize AttestationResponse");
    }
}

public class AttestSevSnpVmRequest
{
    [JsonProperty("report")]
    public required string Report { get; set; }

    [JsonProperty("runtimeData", NullValueHandling = NullValueHandling.Ignore)]
    public RuntimeData? RuntimeData { get; set; }

    [JsonProperty("initTimeData", NullValueHandling = NullValueHandling.Ignore)]
    public InitTimeData? InitTimeData { get; set; }

    [JsonProperty("nonce", NullValueHandling = NullValueHandling.Ignore)]
    public string? Nonce { get; set; }
}

public class AttestationResponse
{
    [JsonProperty("token")]
    public required string Token { get; set; }
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
