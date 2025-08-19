using System.Text.Json;

namespace LogonAudit.CommandProcessors
{
    public class IPInfoCommand(string ipAddress) : CommandProcessorBase
    {
        private readonly string _ipAddress = ipAddress;
        private readonly HttpClient _httpClient = new();

        public override async Task Process()
        {
            try
            {
                NotifyProgress($"Fetching information for IP {_ipAddress}...");
                
                var response = await _httpClient.GetStringAsync($"https://ipinfo.io/{_ipAddress}/json");
                var ipInfo = JsonSerializer.Deserialize<Dictionary<string, string>>(response);

                if (ipInfo != null)
                {
                    foreach (var info in ipInfo)
                    {
                        NotifyProgress($"{info.Key}: {info.Value}");
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                NotifyProgress($"Failed to fetch IP information: {ex.Message}");
                throw;
            }
            catch (JsonException ex)
            {
                NotifyProgress($"Failed to parse IP information: {ex.Message}");
                throw;
            }
        }
    }
}