































using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SIPSorcery.Net
{




    public static class WhipWhepServer
    {
        private static readonly ILogger logger = LogFactory.CreateLogger("SIPSorcery.Net.WhipWhepServer");













        public static async Task<string> AnswerAsync(RTCPeerConnection pc, string offerSdp, bool waitForIceGathering = true)
        {
            if (pc == null)
            {
                throw new ArgumentNullException(nameof(pc));
            }

            if (string.IsNullOrWhiteSpace(offerSdp))
            {
                throw new ArgumentException("The WHIP/WHEP offer SDP was empty.", nameof(offerSdp));
            }

            logger.LogTrace("WHIP/WHEP server applying offer SDP:\n{Sdp}", offerSdp);

            var setResult = pc.setRemoteDescription(new RTCSessionDescriptionInit
            {
                type = RTCSdpType.offer,
                sdp = offerSdp
            });
            if (setResult != SetDescriptionResultEnum.OK)
            {
                throw new ApplicationException($"The WHIP/WHEP offer could not be applied: {setResult}.");
            }



            var answer = pc.createAnswer(new RTCAnswerOptions { X_WaitForIceGatheringToComplete = waitForIceGathering });
            await pc.setLocalDescription(answer).ConfigureAwait(false);

            logger.LogTrace("WHIP/WHEP server answer SDP:\n{Sdp}", answer.sdp);

            return answer.sdp;
        }
    }
}
