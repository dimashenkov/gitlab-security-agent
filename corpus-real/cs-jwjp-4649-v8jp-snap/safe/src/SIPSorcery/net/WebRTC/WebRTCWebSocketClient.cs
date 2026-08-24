

















using System;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SIPSorcery.Net
{






    public class WebRTCWebSocketClient
    {
        private const int MAX_RECEIVE_BUFFER = 8192;
        private const int MAX_SEND_BUFFER = 8192;
        private const int WEB_SOCKET_CONNECTION_TIMEOUT_MS = 10000;

        private static readonly ILogger logger = LogFactory.CreateLogger<WebRTCWebSocketClient>();

        private Uri _webSocketServerUri;
        private Func<Task<RTCPeerConnection>> _createPeerConnection;

        private RTCPeerConnection _pc;
        public RTCPeerConnection RTCPeerConnection => _pc;






        public WebRTCWebSocketClient(
            string webSocketServer,
            Func<Task<RTCPeerConnection>> createPeerConnection)
        {
            if (string.IsNullOrWhiteSpace(webSocketServer))
            {
                throw new ArgumentNullException("The web socket server URI must be supplied.");
            }

            _webSocketServerUri = new Uri(webSocketServer);
            _createPeerConnection = createPeerConnection;
        }






        public async Task Start(CancellationToken cancellation)
        {
            _pc = await _createPeerConnection().ConfigureAwait(false);

            logger.LogDebug("websocket-client attempting to connect to {WebSocketServerUri}.", _webSocketServerUri);

            var webSocketClient = new ClientWebSocket();



            _ = WebSocket.CreateClientBuffer(MAX_RECEIVE_BUFFER, MAX_SEND_BUFFER);
            CancellationTokenSource connectCts = new CancellationTokenSource();
            connectCts.CancelAfter(WEB_SOCKET_CONNECTION_TIMEOUT_MS);
            await webSocketClient.ConnectAsync(_webSocketServerUri, connectCts.Token).ConfigureAwait(false);

            if (webSocketClient.State == WebSocketState.Open)
            {
                logger.LogDebug("websocket-client starting receive task for server {WebSocketServerUri}.", _webSocketServerUri);

                _pc.onicecandidate += async (candidate) =>
                {
                    logger.LogDebug("WebRTCWebSocketClient sending ICE candidate to server.");
                    await webSocketClient.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(candidate.toJSON())), WebSocketMessageType.Text, true, cancellation);
                };

                _ = Task.Run(() => ReceiveFromWebSocket(_pc, webSocketClient, cancellation)).ConfigureAwait(false);
            }
            else
            {
                _pc.Close("web socket connection failure");
            }
        }

        private async Task ReceiveFromWebSocket(RTCPeerConnection pc, ClientWebSocket ws, CancellationToken ct)
        {
            var buffer = new byte[MAX_RECEIVE_BUFFER];
            int posn = 0;

            while (ws.State == WebSocketState.Open &&
                (pc.connectionState == RTCPeerConnectionState.@new || pc.connectionState == RTCPeerConnectionState.connecting))
            {
                WebSocketReceiveResult receiveResult;
                do
                {
                    receiveResult = await ws.ReceiveAsync(new ArraySegment<byte>(buffer, posn, MAX_RECEIVE_BUFFER - posn), ct).ConfigureAwait(false);
                    posn += receiveResult.Count;
                }
                while (!receiveResult.EndOfMessage);

                if (posn > 0)
                {
                    var jsonMsg = Encoding.UTF8.GetString(buffer, 0, posn);
                    string jsonResp = await OnMessage(jsonMsg, pc);

                    if (jsonResp != null)
                    {
                        await ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(jsonResp)), WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
                    }
                }

                posn = 0;
            }

            logger.LogDebug("websocket-client receive loop exiting.");
        }

        private async Task<string> OnMessage(string jsonStr, RTCPeerConnection pc)
        {
            if (RTCIceCandidateInit.TryParse(jsonStr, out var iceCandidateInit))
            {
                logger.LogDebug("Got remote ICE candidate.");
                pc.addIceCandidate(iceCandidateInit);
            }
            else if (RTCSessionDescriptionInit.TryParse(jsonStr, out var descriptionInit))
            {
                logger.LogDebug("Got remote SDP, type {DescriptionType}.", descriptionInit.type);

                var result = pc.setRemoteDescription(descriptionInit);
                if (result != SetDescriptionResultEnum.OK)
                {
                    logger.LogWarning("Failed to set remote description, {Result}.", result);
                    pc.Close("failed to set remote description");
                }

                if (descriptionInit.type == RTCSdpType.offer)
                {
                    var answerSdp = pc.createAnswer(null);
                    await pc.setLocalDescription(answerSdp).ConfigureAwait(false);

                    return answerSdp.toJSON();
                }
            }
            else
            {
                logger.LogWarning("websocket-client could not parse JSON message. {JsonStr}", jsonStr);
            }

            return null;
        }
    }
}
