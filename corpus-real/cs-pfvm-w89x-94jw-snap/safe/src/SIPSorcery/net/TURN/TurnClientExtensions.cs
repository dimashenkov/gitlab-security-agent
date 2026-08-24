















using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SIPSorcery.Net;

public static class TurnClientExtensions
{
    public const int DEFAULT_TURN_ALLOCATION_TIMEOUT_SECONDS = 10;












    public static async Task<MediaStream> UseTurn(this MediaStream mediaStream,
        TurnClient turnClient,
        IPAddress remotePeerIPAddress,
        CancellationToken ct,
        int timeoutSeconds = DEFAULT_TURN_ALLOCATION_TIMEOUT_SECONDS)
    {
        turnClient.SetRtpChannel(mediaStream.GetRTPChannel());

        var relayDestinationEndPoint = await turnClient.GetRelayEndPoint(timeoutSeconds * 1000, ct);

        if (relayDestinationEndPoint != null)
        {
            mediaStream.RtpRelayEndPoint = new TurnRelayEndPoint
            {
                RelayServerEndPoint = turnClient.IceServer.ServerEndPoint,
                RemotePeerRelayEndPoint = relayDestinationEndPoint
            };

            turnClient.CreatePermission(new IPEndPoint(remotePeerIPAddress, 0));
        }

        return mediaStream;
    }
}
