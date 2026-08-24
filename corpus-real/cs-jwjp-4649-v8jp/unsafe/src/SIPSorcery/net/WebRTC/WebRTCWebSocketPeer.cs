
















using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebSocketSharp;
using WebSocketSharp.Server;

namespace SIPSorcery.Net
{





    public class WebRTCWebSocketPeer : WebSocketBehavior
    {
        private static readonly ILogger logger = LogFactory.CreateLogger<WebRTCWebSocketPeer>();

        private RTCPeerConnection _pc;
        public RTCPeerConnection RTCPeerConnection => _pc;




        public RTCOfferOptions OfferOptions { get; set; }




        public RTCAnswerOptions AnswerOptions { get; set; }






        public Func<RTCIceCandidateInit, bool> FilterRemoteICECandidates { get; set; }

        public Func<Task<RTCPeerConnection>> CreatePeerConnection;

        public WebRTCWebSocketPeer()
        { }

        protected override async void OnMessage(MessageEventArgs e)
        {


            if (RTCIceCandidateInit.TryParse(e.Data, out var iceCandidateInit))
            {
                logger.LogDebug("Got remote ICE candidate.");

                bool useCandidate = true;
                if (FilterRemoteICECandidates != null && !string.IsNullOrWhiteSpace(iceCandidateInit.candidate))
                {
                    useCandidate = FilterRemoteICECandidates(iceCandidateInit);
                }

                if (!useCandidate)
                {
                    logger.LogDebug("WebRTCWebSocketPeer excluding ICE candidate due to filter: {Candidate}", iceCandidateInit.candidate);
                }
                else
                {
                    _pc.addIceCandidate(iceCandidateInit);
                }
            }
            else if (RTCSessionDescriptionInit.TryParse(e.Data, out var descriptionInit))
            {
                logger.LogDebug("Got remote SDP, type {DescriptionType}.", descriptionInit.type);
                var result = _pc.setRemoteDescription(descriptionInit);
                if (result != SetDescriptionResultEnum.OK)
                {
                    logger.LogWarning("Failed to set remote description, {Result}.", result);


                    logger.LogTrace("Remote SDP was:\n{Description}", descriptionInit.sdp);

                    _pc.Close("failed to set remote description");
                    this.Close();
                }
                else
                {
                    if (_pc.signalingState == RTCSignalingState.have_remote_offer)
                    {
                        var answerSdp = _pc.createAnswer(AnswerOptions);
                        await _pc.setLocalDescription(answerSdp).ConfigureAwait(false);

                        logger.LogDebug("Sending SDP answer to client {UserEndPoint}.", Context.UserEndPoint);



                        Context.WebSocket.Send(answerSdp.toJSON());
                    }
                }
            }
            else
            {
                logger.LogWarning("websocket-server could not parse JSON message. {MessageData}", e.Data);
            }
        }

        protected override async void OnOpen()
        {
            base.OnOpen();

            logger.LogDebug("Web socket client connection from {UserEndPoint}.", Context.UserEndPoint);

            _pc = await CreatePeerConnection().ConfigureAwait(false);

            _pc.onicecandidate += (iceCandidate) =>
            {
                if (_pc.signalingState == RTCSignalingState.have_remote_offer ||
                    _pc.signalingState == RTCSignalingState.stable)
                {
                    Context.WebSocket.Send(iceCandidate.toJSON());
                }
            };

            if (base.Context.QueryString["role"] != "offer")
            {
                var offerSdp = _pc.createOffer(OfferOptions);
                await _pc.setLocalDescription(offerSdp).ConfigureAwait(false);

                logger.LogDebug("Sending SDP offer to client {UserEndPoint}.", Context.UserEndPoint);



                try
                {
                    Context.WebSocket.Send(offerSdp.toJSON());
                }
                catch (Exception ex)
                {
                    logger.LogError("An error has occurred during the OnOpen event.\n{Exception}.", ex.ToString());
                }
            }
        }

        protected override void OnClose(CloseEventArgs e)
        {
            _pc?.Close("Signalling web socket closed.");
            base.OnClose(e);
        }
    }
}
