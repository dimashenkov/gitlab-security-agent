




















using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public enum RTCSdpType
    {
        answer = 0,
        offer = 1,
        pranswer = 2,
        rollback = 3
    }

    public class RTCOfferOptions
    {





        public bool X_ExcludeIceCandidates;





        public bool X_WaitForIceGatheringToComplete;
    }







    public class RTCAnswerOptions
    {





        public bool X_ExcludeIceCandidates;







        public bool X_WaitForIceGatheringToComplete;
    }

    public class RTCSessionDescription
    {
        public RTCSdpType type;
        public SDP sdp;
    }







    public enum RTCIceCredentialType
    {
        password
    }







    public class RTCIceServer
    {
        public string urls;
        public string username;
        public RTCIceCredentialType credentialType;
        public string credential;

        public static RTCIceServer Parse(string iceServer)
        {
            var fields = iceServer.Split(';');

            return new RTCIceServer
            {
                urls = fields[0],
                username = fields.Length > 1 ? fields[1] : null,
                credential = fields.Length > 2 ? fields[2] : null,
                credentialType = RTCIceCredentialType.password
            };
        }
    }







    public enum RTCIceTransportPolicy
    {
        all,
        relay
    }







    public enum RTCBundlePolicy
    {
        balanced,
        max_compat,
        max_bundle
    }









    public enum RTCRtcpMuxPolicy
    {
        require
    }




    public class RTCDtlsFingerprint
    {



        public string algorithm;





        public string value;

        public override string ToString()
        {

            return $"{algorithm} {value.ToUpper()}";
        }







        public static bool TryParse(string str, out RTCDtlsFingerprint fingerprint)
        {
            fingerprint = null;

            if (string.IsNullOrEmpty(str))
            {
                return false;
            }
            else
            {
                int spaceIndex = str.IndexOf(' ');
                if (spaceIndex == -1)
                {
                    return false;
                }
                else
                {
                    string algStr = str.Substring(0, spaceIndex);
                    string val = str.Substring(spaceIndex + 1);

                    if (!DtlsUtils.IsHashSupported(algStr))
                    {
                        return false;
                    }
                    else
                    {
                        fingerprint = new RTCDtlsFingerprint
                        {
                            algorithm = algStr,
                            value = val
                        };
                        return true;
                    }
                }
            }
        }
    }










    [Obsolete("Use RTCCertificate2 instead")]
    public class RTCCertificate
    {




        public long expires
        {
            get
            {
                if (Certificate == null)
                {
                    return 0;
                }
                else
                {
                    return Certificate.NotAfter.ToUnixTime();
                }
            }
        }

        public X509Certificate2 Certificate;

        public List<RTCDtlsFingerprint> getFingerprints()
        {
            return new List<RTCDtlsFingerprint> { DtlsUtils.Fingerprint(Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(Certificate)) };
        }
    }










    public class RTCCertificate2
    {




        public long expires
        {
            get
            {
                if (Certificate == null)
                {
                    return 0;
                }
                else
                {
                    return Certificate.NotAfter.ToUnixTime();
                }
            }
        }

        public Org.BouncyCastle.X509.X509Certificate Certificate;

        public Org.BouncyCastle.Crypto.AsymmetricKeyParameter PrivateKey;

        public List<RTCDtlsFingerprint> getFingerprints()
        {
            return new List<RTCDtlsFingerprint> { DtlsUtils.Fingerprint(Certificate) };
        }
    }







    public class RTCConfiguration
    {
        public List<RTCIceServer> iceServers;
        public RTCIceTransportPolicy iceTransportPolicy;
        public RTCBundlePolicy bundlePolicy;
        public RTCRtcpMuxPolicy rtcpMuxPolicy;
        public List<RTCCertificate2> certificates2;















        public bool X_DisableExtendedMasterSecretKey;




        public int iceCandidatePoolSize = 0;







        public IPAddress X_BindAddress;





        public bool X_UseRtpFeedbackProfile;











        public bool X_ICEIncludeAllInterfaceAddresses;





        public bool X_UseRsaForDtlsCertificate;




        public int X_GatherTimeoutMs = 30000;
    }







    public enum RTCSignalingState
    {
        stable,
        have_local_offer,
        have_remote_offer,
        have_local_pranswer,
        have_remote_pranswer,
        closed
    }












    public enum RTCPeerConnectionState
    {
        closed,
        failed,
        disconnected,
        @new,
        connecting,
        connected
    }

    public interface IRTCPeerConnection
    {

        RTCSessionDescriptionInit createOffer(RTCOfferOptions options = null);
        RTCSessionDescriptionInit createAnswer(RTCAnswerOptions options = null);
        Task setLocalDescription(RTCSessionDescriptionInit description);
        RTCSessionDescription localDescription { get; }
        RTCSessionDescription currentLocalDescription { get; }
        RTCSessionDescription pendingLocalDescription { get; }
        SetDescriptionResultEnum setRemoteDescription(RTCSessionDescriptionInit description);
        RTCSessionDescription remoteDescription { get; }
        RTCSessionDescription currentRemoteDescription { get; }
        RTCSessionDescription pendingRemoteDescription { get; }
        void addIceCandidate(RTCIceCandidateInit candidate = null);
        RTCSignalingState signalingState { get; }
        RTCIceGatheringState iceGatheringState { get; }
        RTCIceConnectionState iceConnectionState { get; }
        RTCPeerConnectionState connectionState { get; }
        bool canTrickleIceCandidates { get; }
        void restartIce();
        RTCConfiguration getConfiguration();
        void setConfiguration(RTCConfiguration configuration = null);
        void close();
        event Action onnegotiationneeded;
        event Action<RTCIceCandidate> onicecandidate;
        event Action<RTCIceCandidate, string> onicecandidateerror;
        event Action onsignalingstatechange;
        event Action<RTCIceConnectionState> oniceconnectionstatechange;
        event Action<RTCIceGatheringState> onicegatheringstatechange;
        event Action<RTCPeerConnectionState> onconnectionstatechange;











    };









    public interface IRTCRtpSender
    {
        MediaStreamTrack track { get; }







    };







    public interface IRTCRtpReceiver
    {
        MediaStreamTrack track { get; }






    };
}
