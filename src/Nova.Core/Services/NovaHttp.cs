using System.Net;

namespace Nova.Core.Services;

public static class NovaHttp
{
    public const string UserAgent = "NovaDesktopSecurity/1.0 (+https://perasoft.com)";

    public static HttpClient Shared { get; } = Create(TimeSpan.FromSeconds(20));

    public static HttpClient Create(TimeSpan timeout, HttpMessageHandler? handler = null)
    {
        handler ??= new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        };
        var client = new HttpClient(handler) { Timeout = timeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }
}
