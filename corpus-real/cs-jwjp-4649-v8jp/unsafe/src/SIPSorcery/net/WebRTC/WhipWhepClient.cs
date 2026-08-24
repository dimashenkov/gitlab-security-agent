

































using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SIPSorcery.Net
{





    public class WhipWhepClient : IDisposable
    {
        private const string SDP_CONTENT_TYPE = "application/sdp";
        private const int ERROR_BODY_MAX_CHARS = 200;

        private static readonly ILogger logger = LogFactory.CreateLogger<WhipWhepClient>();

        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;





        public Uri ResourceUrl { get; private set; }


        public WhipWhepClient() : this(null)
        { }





        public WhipWhepClient(HttpClient httpClient)
        {
            _ownsHttpClient = httpClient == null;
            _httpClient = httpClient ?? new HttpClient();
        }






        public Task PublishAsync(RTCPeerConnection pc, string endpointUrl, string bearerToken = null, CancellationToken ct = default)
            => ExchangeAsync(pc, endpointUrl, bearerToken, ct);






        public Task PlayAsync(RTCPeerConnection pc, string endpointUrl, string bearerToken = null, CancellationToken ct = default)
            => ExchangeAsync(pc, endpointUrl, bearerToken, ct);

        private async Task ExchangeAsync(RTCPeerConnection pc, string endpointUrl, string bearerToken, CancellationToken ct)
        {
            if (pc == null)
            {
                throw new ArgumentNullException(nameof(pc));
            }

            if (!Uri.TryCreate(endpointUrl, UriKind.Absolute, out var endpoint) ||
                (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps))
            {
                throw new ArgumentException($"The WHIP/WHEP endpoint '{endpointUrl}' is not an absolute HTTP or HTTPS URL.", nameof(endpointUrl));
            }



            var offer = pc.createOffer(new RTCOfferOptions { X_WaitForIceGatheringToComplete = true });
            await pc.setLocalDescription(offer).ConfigureAwait(false);

            logger.LogDebug("WHIP/WHEP posting SDP offer to {Endpoint}.", endpoint);
            logger.LogTrace("WHIP/WHEP offer SDP:\n{Sdp}", offer.sdp);

            using (var request = new HttpRequestMessage(HttpMethod.Post, endpoint))
            {
                request.Content = new StringContent(offer.sdp, Encoding.UTF8, SDP_CONTENT_TYPE);
                if (!string.IsNullOrWhiteSpace(bearerToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
                }

                using (var response = await _httpClient.SendAsync(request, ct).ConfigureAwait(false))
                {
                    string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                    logger.LogTrace("WHIP/WHEP answer SDP ({StatusCode}):\n{Sdp}", response.StatusCode, body);

                    if (!response.IsSuccessStatusCode)
                    {
                        string detail = body != null && body.Length > ERROR_BODY_MAX_CHARS ? body.Substring(0, ERROR_BODY_MAX_CHARS) : body;
                        throw new ApplicationException($"The WHIP/WHEP endpoint {endpoint} returned HTTP {(int)response.StatusCode}. {detail}".TrimEnd());
                    }



                    if (response.Headers.Location != null)
                    {
                        ResourceUrl = response.Headers.Location.IsAbsoluteUri
                            ? response.Headers.Location
                            : new Uri(endpoint, response.Headers.Location);
                    }

                    var setResult = pc.setRemoteDescription(new RTCSessionDescriptionInit
                    {
                        type = RTCSdpType.answer,
                        sdp = body
                    });
                    if (setResult != SetDescriptionResultEnum.OK)
                    {
                        throw new ApplicationException($"The WHIP/WHEP SDP answer from {endpoint} could not be applied: {setResult}.");
                    }
                }
            }

            logger.LogDebug("WHIP/WHEP answer applied for {Endpoint} (resource {ResourceUrl}).", endpoint, ResourceUrl);
        }





        public async Task DeleteAsync(string bearerToken = null, CancellationToken ct = default)
        {
            var resource = ResourceUrl;
            if (resource == null)
            {
                return;
            }

            try
            {
                using (var request = new HttpRequestMessage(HttpMethod.Delete, resource))
                {
                    if (!string.IsNullOrWhiteSpace(bearerToken))
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
                    }
                    await _httpClient.SendAsync(request, ct).ConfigureAwait(false);
                }
            }
            catch (Exception excp)
            {
                logger.LogDebug("WHIP/WHEP session delete failed: {Error}", excp.Message);
            }
        }

        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
        }
    }
}
