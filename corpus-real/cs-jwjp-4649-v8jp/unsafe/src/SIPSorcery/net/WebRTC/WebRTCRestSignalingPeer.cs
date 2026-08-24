


















using System;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SIPSorcery.Net
{
    public enum WebRTCSignalTypesEnum
    {
        any = 0,
        sdp = 2,
        ice = 3
    }





    public class WebRTCRestSignalingPeer
    {
        private const int REST_SERVER_POLL_PERIOD = 2000;
        private const int CONNECTION_RETRY_PERIOD = 5000;

        private static readonly ILogger logger = LogFactory.CreateLogger<WebRTCRestSignalingPeer>();

        private Uri _restServerUri;
        private string _ourID;
        private string _theirID;
        private bool _isReceiving;
        private Task _receiveTask;
        private Func<Task<RTCPeerConnection>> _createPeerConnection;

        private RTCPeerConnection _pc;
        public RTCPeerConnection RTCPeerConnection => _pc;




        public RTCOfferOptions OfferOptions { get; set; }




        public RTCAnswerOptions AnswerOptions { get; set; }






        public Func<RTCIceCandidateInit, bool> FilterRemoteICECandidates { get; set; }








        public WebRTCRestSignalingPeer(
            string restServerUri,
            string ourID,
            string theirID,
            Func<Task<RTCPeerConnection>> createPeerConnection)
        {
            if (string.IsNullOrWhiteSpace(restServerUri))
            {
                throw new ArgumentNullException($"The {nameof(restServerUri)} parameter must be set.");
            }

            if (string.IsNullOrWhiteSpace(ourID))
            {
                throw new ArgumentNullException(nameof(ourID));
            }

            if (string.IsNullOrWhiteSpace(theirID))
            {
                throw new ArgumentNullException(nameof(theirID));
            }

            _restServerUri = new Uri(restServerUri);
            _ourID = ourID;
            _theirID = theirID;
            _createPeerConnection = createPeerConnection;
        }






        public async Task Start(CancellationTokenSource cancellation)
        {
            var peerConnectedCancellation = new CancellationTokenSource();
            CancellationTokenSource linkedSource = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token, peerConnectedCancellation.Token);

            var restClient = new HttpClient();

            _pc = await _createPeerConnection().ConfigureAwait(false);
            _pc.onconnectionstatechange += (state) =>
            {
                if (_isReceiving && !(state == RTCPeerConnectionState.@new || state == RTCPeerConnectionState.connecting))
                {
                    logger.LogDebug("cancelling HTTP receive task.");
                    peerConnectedCancellation?.Cancel();
                }
            };
            _pc.onicecandidate += async (cand) =>
            {
                if (cand.type != RTCIceCandidateType.host)
                {

                    logger.LogDebug("webrtc-rest onicecandidate: {CandidateStr}.", cand.ToShortString());
                    await SendToSignalingServer(restClient, cand.toJSON(), WebRTCSignalTypesEnum.ice);
                }
            };

            logger.LogDebug("webrtc-rest starting receive task for server {RestServerUri}, our ID {OurID} and their ID {TheirID}.", _restServerUri, _ourID, _theirID);

            _receiveTask = Task.Run(() => ReceiveFromNSS(restClient, _pc, linkedSource.Token));
        }




        private async Task SendOffer(HttpClient httpClient)
        {
            logger.LogDebug("webrtc-rest sending initial SDP offer to server.");

            var offerSdp = _pc.createOffer(OfferOptions);

            await _pc.setLocalDescription(offerSdp).ConfigureAwait(false);

            await SendToSignalingServer(httpClient, offerSdp.toJSON(), WebRTCSignalTypesEnum.sdp).ConfigureAwait(false);
        }

        private async Task SendToSignalingServer(HttpClient httpClient, string jsonStr, WebRTCSignalTypesEnum sendType)
        {
            var content = new StringContent(jsonStr, Encoding.UTF8, "application/json");
            var res = await httpClient.PutAsync($"{_restServerUri}/{sendType}/{_ourID}/{_theirID}", content).ConfigureAwait(false);

            logger.LogDebug("webrtc-rest PUT result for {RestServerUri}/{SendType}/{OurID}/{TheirID} {StatusCode}.", _restServerUri, sendType, _ourID, _theirID, res.StatusCode);
        }

        private async Task ReceiveFromNSS(HttpClient httpClient, RTCPeerConnection pc, CancellationToken ct)
        {
            _isReceiving = true;

            try
            {
                bool isInitialReceive = true;

                while (!ct.IsCancellationRequested)
                {
                    HttpResponseMessage res = null;

                    try
                    {
                        res = await httpClient.GetAsync($"{_restServerUri}/{_ourID}/{_theirID}", ct).ConfigureAwait(false);
                    }
                    catch (HttpRequestException e)
                        when (e.InnerException is SocketException && (e.InnerException as SocketException).SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        if (isInitialReceive)
                        {
                            logger.LogDebug("webrtc-rest server initial connection attempt failed, will retry in {RetryPeriod}ms.", CONNECTION_RETRY_PERIOD);
                            await Task.Delay(CONNECTION_RETRY_PERIOD).ConfigureAwait(false);
                            continue;
                        }
                        else
                        {
                            logger.LogWarning("webrtc-rest server connection attempt failed.");
                            break;
                        }
                    }

                    if (res.StatusCode == HttpStatusCode.OK)
                    {
                        var signal = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
                        var resp = await OnMessage(signal, pc).ConfigureAwait(false);

                        if (resp != null)
                        {
                            await SendToSignalingServer(httpClient, resp, WebRTCSignalTypesEnum.sdp).ConfigureAwait(false);
                        }
                    }
                    else if (res.StatusCode == HttpStatusCode.NoContent)
                    {
                        if (isInitialReceive)
                        {


                            await SendOffer(httpClient).ConfigureAwait(false);
                        }
                        else
                        {

                            await Task.Delay(REST_SERVER_POLL_PERIOD).ConfigureAwait(false);
                        }
                    }
                    else
                    {
                        throw new ApplicationException($"Get request to REST server failed with response code {res.StatusCode}.");
                    }

                    isInitialReceive = false;
                }
            }
            catch (OperationCanceledException)
            { }
            catch (Exception excp)
            {
                logger.LogError(excp, "Exception receiving webrtc signal. {ErrorMessage}", excp.Message);
            }
            finally
            {
                logger.LogDebug("webrtc-rest receive task exiting.");
                _isReceiving = false;
            }
        }

        private async Task<string> OnMessage(string signal, RTCPeerConnection pc)
        {
            string sdpAnswer = null;

            if (RTCIceCandidateInit.TryParse(signal, out var iceCandidateInit))
            {
                logger.LogDebug("Got remote ICE candidate, {Candidate}", iceCandidateInit.candidate);

                bool useCandidate = true;
                if (FilterRemoteICECandidates != null && !string.IsNullOrWhiteSpace(iceCandidateInit.candidate))
                {
                    useCandidate = FilterRemoteICECandidates(iceCandidateInit);
                }

                if (!useCandidate)
                {
                    logger.LogDebug("WebRTCRestPeer excluding ICE candidate due to filter: {Candidate}", iceCandidateInit.candidate);
                }
                else
                {
                    _pc.addIceCandidate(iceCandidateInit);
                }
            }
            else if (RTCSessionDescriptionInit.TryParse(signal, out var descriptionInit))
            {
                logger.LogDebug("Got remote SDP, type {SdpType}.", descriptionInit.type);


                var result = pc.setRemoteDescription(descriptionInit);
                
                if (result != SetDescriptionResultEnum.OK)
                {
                    logger.LogWarning("Failed to set remote description, {Result}.", result);
                    pc.Close("failed to set remote description");
                }
                else if (descriptionInit.type == RTCSdpType.offer)
                {
                    var answerSdp = pc.createAnswer(AnswerOptions);
                    await pc.setLocalDescription(answerSdp).ConfigureAwait(false);

                    sdpAnswer = answerSdp.toJSON();
                }
            }
            else
            {
                logger.LogWarning("webrtc-rest could not parse JSON message. {Signal}", signal);
            }

            return sdpAnswer;
        }
    }
}
