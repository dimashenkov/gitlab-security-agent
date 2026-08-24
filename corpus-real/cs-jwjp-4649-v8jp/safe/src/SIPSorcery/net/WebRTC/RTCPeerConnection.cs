



































using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.SIP.App;
using SIPSorcery.Sys;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SIPSorcery.Net.SharpSRTP.DTLS;
using SIPSorcery.Net.SharpSRTP.DTLSSRTP;

namespace SIPSorcery.Net
{






    public class RTCSessionDescriptionInit
    {



        public RTCSdpType type { get; set; }




        public string sdp { get; set; }

        public string toJSON()
        {
            return TinyJson.JSONWriter.ToJson(this);
        }

        public static bool TryParse(string json, out RTCSessionDescriptionInit init)
        {
            init = null;

            if (string.IsNullOrWhiteSpace(json))
            {
                return false;
            }
            else
            {
                init = TinyJson.JSONParser.FromJson<RTCSessionDescriptionInit>(json);


                return init != null &&
                    init.sdp != null;
            }
        }
    }









    public class RTCPeerConnection : RTPSession, IRTCPeerConnection
    {


        private const string RTP_MEDIA_NON_FEEDBACK_PROFILE = "UDP/TLS/RTP/SAVP";
        private const string RTP_MEDIA_FEEDBACK_PROFILE = "UDP/TLS/RTP/SAVPF";
        private const string RTP_MEDIA_DATACHANNEL_DTLS_PROFILE = "DTLS/SCTP";
        private const string RTP_MEDIA_DATACHANNEL_UDPDTLS_PROFILE = "UDP/DTLS/SCTP";
        private const string SDP_DATACHANNEL_FORMAT_ID = "webrtc-datachannel";
        private const string RTCP_MUX_ATTRIBUTE = "a=rtcp-mux";
        private const string BUNDLE_ATTRIBUTE = "BUNDLE";
        private const string ICE_OPTIONS = "ice2,trickle";
        private const string NORMAL_CLOSE_REASON = "normal";
        private const ushort SCTP_DEFAULT_PORT = 5000;







        private const int SCTP_ASSOCIATE_TIMEOUT_SECONDS = 2;

        private new readonly string RTP_MEDIA_PROFILE = RTP_MEDIA_NON_FEEDBACK_PROFILE;
        private readonly string RTCP_ATTRIBUTE = $"a=rtcp:{SDP.IGNORE_RTP_PORT_NUMBER} IN IP4 0.0.0.0";

        public string SessionID { get; private set; }
        public string SdpSessionID { get; private set; }
        public string LocalSdpSessionID { get; private set; }

        private RtpIceChannel _rtpIceChannel;

        private readonly RTCDataChannelCollection _dataChannels;
        public IReadOnlyCollection<RTCDataChannel> DataChannels => _dataChannels;

        private Org.BouncyCastle.Tls.Certificate _dtlsCertificate;
        private Org.BouncyCastle.Crypto.AsymmetricKeyParameter _dtlsPrivateKey;
        private BcTlsCrypto _crypto;
        private DtlsSrtpTransport _dtlsHandle;
        private Task _iceInitiateGatheringTask;
        private readonly TaskCompletionSource<bool> _iceCompletedGatheringTask = new();

        private Dictionary<string, int> _rtpExtensionsUsed;






        private List<RTCIceCandidate> _applicationIceCandidates = new List<RTCIceCandidate>();




        public IceRolesEnum IceRole { get; set; } = IceRolesEnum.actpass;





        public RTCDtlsFingerprint RemotePeerDtlsFingerprint { get; private set; }

        public string DtlsCertificateSignatureAlgorithm { get; private set; } = string.Empty;

        public bool IsDtlsNegotiationComplete { get; private set; } = false;

        public RTCSessionDescription localDescription { get; private set; }

        public RTCSessionDescription remoteDescription { get; private set; }

        public RTCSessionDescription currentLocalDescription => localDescription;

        public RTCSessionDescription pendingLocalDescription => null;

        public RTCSessionDescription currentRemoteDescription => remoteDescription;

        public RTCSessionDescription pendingRemoteDescription => null;

        public RTCSignalingState signalingState { get; private set; } = RTCSignalingState.closed;

        public RTCIceGatheringState iceGatheringState
        {
            get
            {
                return _rtpIceChannel != null ? _rtpIceChannel.IceGatheringState : RTCIceGatheringState.@new;
            }
        }

        public RTCIceConnectionState iceConnectionState
        {
            get
            {
                return _rtpIceChannel != null ? _rtpIceChannel.IceConnectionState : RTCIceConnectionState.@new;
            }
        }

        public RTCPeerConnectionState connectionState { get; private set; } = RTCPeerConnectionState.@new;

        public bool canTrickleIceCandidates { get => true; }

        private RTCConfiguration _configuration;





        public RTCDtlsFingerprint DtlsCertificateFingerprint { get; private set; }








        public RTCSctpTransport sctp { get; private set; }





        public event Action onnegotiationneeded;

        private event Action<RTCIceCandidate> _onIceCandidate;



        public event Action<RTCIceCandidate> onicecandidate
        {
            add
            {
                var notifyIce = _onIceCandidate == null && value != null;
                _onIceCandidate += value;
                if (notifyIce)
                {
                    foreach (var ice in _rtpIceChannel.Candidates)
                    {
                        _onIceCandidate?.Invoke(ice);
                    }
                }
            }
            remove
            {
                _onIceCandidate -= value;
            }
        }

        protected CancellationTokenSource _cancellationSource = new CancellationTokenSource();
        protected object _renegotiationLock = new object();
        protected volatile bool _requireRenegotiation = true;

        public override bool RequireRenegotiation
        {
            get
            {
                return _requireRenegotiation;
            }

            protected internal set
            {
                lock (_renegotiationLock)
                {
                    _requireRenegotiation = value;








                }


                if (!_requireRenegotiation || signalingState != RTCSignalingState.stable)
                {
                    CancelOnNegotiationNeededTask();
                }

                else
                {
                    StartOnNegotiationNeededTask();
                }
            }
        }




        public event Action<RTCIceCandidate, string> onicecandidateerror;





        public event Action onsignalingstatechange;




        public event Action<RTCIceConnectionState> oniceconnectionstatechange;




        public event Action<RTCIceGatheringState> onicegatheringstatechange;






        public event Action<RTCPeerConnectionState> onconnectionstatechange;




        public event Action<RTCDataChannel> ondatachannel;




        public RTCPeerConnection() :
            this(null)
        { }





        public RTCPeerConnection(RTCConfiguration configuration, int bindPort = 0, PortRange portRange = null, Boolean videoAsPrimary = false) :
            base(true, true, true, configuration?.X_BindAddress, bindPort, portRange)
        {
            _crypto = new BcTlsCrypto();
            _dataChannels = new RTCDataChannelCollection(useEvenIds: () => _dtlsHandle.IsClient);

            if (_configuration != null &&
               _configuration.iceTransportPolicy == RTCIceTransportPolicy.relay &&
               _configuration.iceServers?.Count == 0)
            {
                throw new ApplicationException("RTCPeerConnection must have at least one ICE server specified for a relay only transport policy.");
            }

            if (configuration != null)
            {
                _configuration = configuration;





                if (!InitializeCertificates(configuration))
                {
                    logger.LogDebug("No DTLS certificate is provided in the configuration");
                }

                if (_configuration.X_UseRtpFeedbackProfile)
                {
                    RTP_MEDIA_PROFILE = RTP_MEDIA_FEEDBACK_PROFILE;
                }
            }
            else
            {
                _configuration = new RTCConfiguration();
            }

            if (_dtlsCertificate == null)
            {

                (_dtlsCertificate, _dtlsPrivateKey) = DtlsUtils.CreateSelfSignedTlsCert(_crypto, useRsa: _configuration.X_UseRsaForDtlsCertificate);
            }

            DtlsCertificateFingerprint = DtlsUtils.Fingerprint(_dtlsCertificate);

            SessionID = Guid.NewGuid().ToString();
            LocalSdpSessionID = Crypto.GetRandomInt(5).ToString();



            addSingleTrack(videoAsPrimary);

            _rtpIceChannel = GetRtpChannel();


            if (_remoteEndpointTranslator != null)
            {
                _rtpIceChannel.RemoteEndpointTranslator = _remoteEndpointTranslator;
            }

            _rtpIceChannel.OnIceCandidate += (candidate) => _onIceCandidate?.Invoke(candidate);
            _rtpIceChannel.OnIceConnectionStateChange += IceConnectionStateChange;
            _rtpIceChannel.OnIceGatheringStateChange += (state) => onicegatheringstatechange?.Invoke(state);
            _rtpIceChannel.OnIceGatheringStateChange += (state) =>
            {
                if (state == RTCIceGatheringState.complete) { _iceCompletedGatheringTask.TrySetResult(true); }
            };
            _rtpIceChannel.OnIceCandidateError += (candidate, error) => onicecandidateerror?.Invoke(candidate, error);

            OnRtpClosed += Close;
            OnRtcpBye += Close;


            onnegotiationneeded += CancelOnNegotiationNeededTask;

            sctp = new RTCSctpTransport(SCTP_DEFAULT_PORT, SCTP_DEFAULT_PORT, _rtpIceChannel.RTPPort);

            onnegotiationneeded?.Invoke();





            _iceInitiateGatheringTask = Task.Run(_rtpIceChannel.StartGathering);
        }

        private bool InitializeCertificates(RTCConfiguration configuration)
        {
            if (configuration.certificates2 == null || configuration.certificates2.Count == 0)
            {
                return false;
            }

            _dtlsCertificate = new Certificate(new[] { new BcTlsCertificate(_crypto, configuration.certificates2[0].Certificate.CertificateStructure) });
            _dtlsPrivateKey = configuration.certificates2[0].PrivateKey;

            return true;
        }





        private async void IceConnectionStateChange(RTCIceConnectionState iceState)
        {
            oniceconnectionstatechange?.Invoke(iceConnectionState);

            if (iceState == RTCIceConnectionState.connected && _rtpIceChannel.NominatedEntry != null)
            {
                if (_dtlsHandle != null)
                {
                    if (base.PrimaryStream.DestinationEndPoint?.Address.Equals(_rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint.Address) == false ||
                        base.PrimaryStream.DestinationEndPoint?.Port != _rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint.Port)
                    {

                        var connectedEP = _rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint;

                        SetGlobalDestination(connectedEP, connectedEP);
                        logger.LogDebug("ICE changing connected remote end point to {connectedEP}.", connectedEP);
                    }

                    if (connectionState == RTCPeerConnectionState.disconnected ||
                        connectionState == RTCPeerConnectionState.failed)
                    {

                        connectionState = RTCPeerConnectionState.connected;
                        onconnectionstatechange?.Invoke(connectionState);
                    }
                }
                else
                {
                    connectionState = RTCPeerConnectionState.connecting;
                    onconnectionstatechange?.Invoke(connectionState);

                    var connectedEP = _rtpIceChannel.NominatedEntry.RemoteCandidate.DestinationEndPoint;

                    SetGlobalDestination(connectedEP, connectedEP);
                    logger.LogDebug("ICE connected to remote end point {connectedEP}.", connectedEP);

                    bool disableDtlsExtendedMasterSecret = _configuration != null && _configuration.X_DisableExtendedMasterSecretKey;

                    _dtlsHandle = new DtlsSrtpTransport(
                                IceRole == IceRolesEnum.active ?
                                new DtlsSrtpClient(_crypto, _dtlsCertificate, _dtlsPrivateKey, _configuration.X_UseRsaForDtlsCertificate ? SignatureAlgorithm.rsa : SignatureAlgorithm.ecdsa)
                                { ForceUseExtendedMasterSecret = !disableDtlsExtendedMasterSecret } :
                                new DtlsSrtpServer(_crypto, _dtlsCertificate, _dtlsPrivateKey, _configuration.X_UseRsaForDtlsCertificate ? SignatureAlgorithm.rsa : SignatureAlgorithm.ecdsa)
                                { ForceUseExtendedMasterSecret = !disableDtlsExtendedMasterSecret, ForceDisableMKI = true }
                                );

                    _dtlsHandle.OnAlert += OnDtlsAlert;

                    logger.LogDebug("Starting DLS handshake with role {IceRole}.", IceRole);

                    try
                    {
                        bool handshakeResult = await Task.Run(() => DoDtlsHandshake(_dtlsHandle)).ConfigureAwait(false);

                        connectionState = handshakeResult ? RTCPeerConnectionState.connected : connectionState = RTCPeerConnectionState.failed;
                        onconnectionstatechange?.Invoke(connectionState);

                        if (connectionState == RTCPeerConnectionState.connected)
                        {
                            await base.Start().ConfigureAwait(false);
                            await InitialiseSctpTransport().ConfigureAwait(false);
                        }
                    }
                    catch (Exception excp)
                    {
                        logger.LogWarning(excp, "RTCPeerConnection DTLS handshake failed. {ErrorMessage}", excp.Message);




                        Close("dtls handshake failed");
                    }
                }
            }

            if (iceConnectionState == RTCIceConnectionState.checking)
            {




            }
            else if (iceConnectionState == RTCIceConnectionState.disconnected)
            {
                if (connectionState == RTCPeerConnectionState.connected)
                {
                    connectionState = RTCPeerConnectionState.disconnected;
                    onconnectionstatechange?.Invoke(connectionState);
                }
                else
                {
                    connectionState = RTCPeerConnectionState.failed;
                    onconnectionstatechange?.Invoke(connectionState);
                }
            }
            else if (iceConnectionState == RTCIceConnectionState.failed)
            {
                connectionState = RTCPeerConnectionState.failed;
                onconnectionstatechange?.Invoke(connectionState);
            }
        }






        protected override RTPChannel CreateRtpChannel()
        {
            if (rtpSessionConfig.IsMediaMultiplexed)
            {
                if (MultiplexRtpChannel != null)
                {
                    return MultiplexRtpChannel;
                }
            }

            var rtpIceChannel = new RtpIceChannel(
            _configuration?.X_BindAddress,
            RTCIceComponent.rtp,
            _configuration?.iceServers,
            _configuration != null ? _configuration.iceTransportPolicy : RTCIceTransportPolicy.all,
            _configuration != null ? _configuration.X_ICEIncludeAllInterfaceAddresses : false,
            rtpSessionConfig.BindPort == 0 ? 0 : rtpSessionConfig.BindPort + m_rtpChannelsCount * 2,
            rtpSessionConfig.RtpPortRange);

            if (rtpSessionConfig.IsMediaMultiplexed)
            {
                MultiplexRtpChannel = rtpIceChannel;
            }

            rtpIceChannel.OnRTPDataReceived += OnRTPDataReceived;


            rtpIceChannel.Start();

            m_rtpChannelsCount++;

            return rtpIceChannel;
        }










        public Task setLocalDescription(RTCSessionDescriptionInit init)
        {
            localDescription = new RTCSessionDescription { type = init.type, sdp = SDP.ParseSDPDescription(init.sdp) };

            if (init.type == RTCSdpType.offer)
            {
                _rtpIceChannel.IsController = true;
            }

            if (signalingState == RTCSignalingState.have_remote_offer)
            {
                signalingState = RTCSignalingState.stable;
                onsignalingstatechange?.Invoke();
            }
            else
            {
                signalingState = RTCSignalingState.have_local_offer;
                onsignalingstatechange?.Invoke();
            }

            return Task.CompletedTask;
        }











        public override SetDescriptionResultEnum SetRemoteDescription(SdpType sdpType, SDP sessionDescription)
        {
            RTCSessionDescriptionInit init = new RTCSessionDescriptionInit
            {
                sdp = sessionDescription.ToString(),
                type = (sdpType == SdpType.answer) ? RTCSdpType.answer : RTCSdpType.offer
            };

            return setRemoteDescription(init);
        }





        public SetDescriptionResultEnum setRemoteDescription(RTCSessionDescriptionInit init)
        {
            remoteDescription = new RTCSessionDescription { type = init.type, sdp = SDP.ParseSDPDescription(init.sdp) };

            SDP remoteSdp = remoteDescription.sdp;


            _rtpExtensionsUsed ??= new Dictionary<string, int>();
            foreach (var ann in remoteSdp.Media)
            {
                if ((ann.Media == SDPMediaTypesEnum.audio) || (ann.Media == SDPMediaTypesEnum.video))
                {
                    var extensions = ann.HeaderExtensions?.Values;
                    if (extensions != null)
                    {
                        foreach (var extension in extensions)
                        {
                            logger.LogDebug("[setRemoteDescription] - Extension:[{Id} - {Uri}]", extension.Id, extension.Uri);
                            _rtpExtensionsUsed[extension.Uri] = extension.Id;
                        }
                    }
                }
            }

            SdpType sdpType = (init.type == RTCSdpType.offer) ? SdpType.offer : SdpType.answer;

            switch (signalingState)
            {
                case var sigState when sigState == RTCSignalingState.have_local_offer && sdpType == SdpType.offer:
                    logger.LogWarning("RTCPeerConnection received an SDP offer but was already in {SignalingState} state. Remote offer rejected.", sigState);
                    return SetDescriptionResultEnum.WrongSdpTypeOfferAfterOffer;
            }

            var setResult = base.SetRemoteDescription(sdpType, remoteSdp);

            if (setResult == SetDescriptionResultEnum.OK)
            {
                string remoteIceUser = remoteSdp.IceUfrag;
                string remoteIcePassword = remoteSdp.IcePwd;
                string dtlsFingerprint = remoteSdp.DtlsFingerprint;
                IceRolesEnum? remoteIceRole = remoteSdp.IceRole;

                foreach (var ann in remoteSdp.Media)
                {
                    if (remoteIceUser == null || remoteIcePassword == null || dtlsFingerprint == null || remoteIceRole == null)
                    {
                        remoteIceUser = remoteIceUser ?? ann.IceUfrag;
                        remoteIcePassword = remoteIcePassword ?? ann.IcePwd;
                        dtlsFingerprint = dtlsFingerprint ?? ann.DtlsFingerprint;
                        remoteIceRole = remoteIceRole ?? ann.IceRole;
                    }


                    if (ann.Media == SDPMediaTypesEnum.application &&
                        ann.MediaFormats.Count() == 1 &&
                        ann.ApplicationMediaFormats.Single().Key == SDP_DATACHANNEL_FORMAT_ID)
                    {
                        if (ann.Transport == RTP_MEDIA_DATACHANNEL_DTLS_PROFILE ||
                            ann.Transport == RTP_MEDIA_DATACHANNEL_UDPDTLS_PROFILE)
                        {
                            dtlsFingerprint = dtlsFingerprint ?? ann.DtlsFingerprint;
                            remoteIceRole = remoteIceRole ?? remoteSdp.IceRole;
                        }
                        else
                        {
                            logger.LogWarning("The remote SDP requested an unsupported data channel transport of {Transport}.", ann.Transport);
                            return SetDescriptionResultEnum.DataChannelTransportNotSupported;
                        }
                    }
                }

                SdpSessionID = remoteSdp.SessionId;

                if (remoteSdp.IceImplementation == IceImplementationEnum.lite)
                {
                    _rtpIceChannel.IsController = true;
                }
                if (init.type == RTCSdpType.answer)
                {
                    _rtpIceChannel.IsController = true;
                    IceRole = remoteIceRole == IceRolesEnum.passive ? IceRolesEnum.active : IceRolesEnum.passive;
                }

                else
                {

                    IceRole = IceRolesEnum.active;
                }

                if (remoteIceUser != null && remoteIcePassword != null)
                {
                    _rtpIceChannel.SetRemoteCredentials(remoteIceUser, remoteIcePassword);
                }

                if (!string.IsNullOrWhiteSpace(dtlsFingerprint))
                {
                    dtlsFingerprint = dtlsFingerprint.Trim().ToLower();
                    if (RTCDtlsFingerprint.TryParse(dtlsFingerprint, out var remoteFingerprint))
                    {
                        RemotePeerDtlsFingerprint = remoteFingerprint;
                    }
                    else
                    {
                        logger.LogWarning("The DTLS fingerprint was invalid or not supported.");
                        return SetDescriptionResultEnum.DtlsFingerprintDigestNotSupported;
                    }
                }
                else
                {
                    logger.LogWarning("The DTLS fingerprint was missing from the remote party's session description.");
                    return SetDescriptionResultEnum.DtlsFingerprintMissing;
                }



                if (remoteSdp.IceCandidates != null)
                {
                    foreach (var iceCandidate in remoteSdp.IceCandidates)
                    {
                        addIceCandidate(new RTCIceCandidateInit { candidate = iceCandidate });
                    }
                }

                ResetRemoteSDPSsrcAttributes();
                foreach (var media in remoteSdp.Media)
                {
                    if (media.IceCandidates != null)
                    {
                        foreach (var iceCandidate in media.IceCandidates)
                        {
                            addIceCandidate(new RTCIceCandidateInit { candidate = iceCandidate });
                        }
                    }

                    AddRemoteSDPSsrcAttributes(media.Media, media.SsrcAttributes);
                }

                LogRemoteSDPSsrcAttributes();

                UpdatedSctpDestinationPort();

                if (init.type == RTCSdpType.offer)
                {
                    signalingState = RTCSignalingState.have_remote_offer;
                    onsignalingstatechange?.Invoke();
                }
                else
                {
                    signalingState = RTCSignalingState.stable;
                    onsignalingstatechange?.Invoke();
                }




                foreach (var nonHostCand in _rtpIceChannel.Candidates.Where(x => x.type != RTCIceCandidateType.host))
                {
                    _onIceCandidate?.Invoke(nonHostCand);
                }
            }

            return setResult;
        }





        public override void Close(string reason)
        {
            if (!IsClosed)
            {
                logger.LogDebug("Peer connection closed with reason {Reason}.", reason != null ? reason : "<none>");


                if (DataChannels?.Count > 0)
                {
                    foreach (var dc in DataChannels)
                    {
                        dc?.close();
                    }
                }

                _rtpIceChannel?.Close();
                _dtlsHandle?.Close();

                sctp?.Close();

                base.Close(reason);

                connectionState = RTCPeerConnectionState.closed;
                onconnectionstatechange?.Invoke(RTCPeerConnectionState.closed);
            }
        }




        public void close()
        {
            Close(NORMAL_CLOSE_REASON);
        }









        public RTCSessionDescriptionInit createOffer(RTCOfferOptions options = null)
        {
            List<MediaStream> mediaStreamList = GetMediaStreams();

            foreach (var mediaStream in mediaStreamList)
            {
                if (mediaStream.LocalTrack != null && mediaStream.LocalTrack.StreamStatus == MediaStreamStatusEnum.Inactive)
                {
                    mediaStream.LocalTrack.StreamStatus = mediaStream.LocalTrack.DefaultStreamStatus;
                }
            }

            bool excludeIceCandidates = options != null && options.X_ExcludeIceCandidates;
            bool waitForIceGatheringToComplete = options != null && options.X_WaitForIceGatheringToComplete;

            var offerSdp = createBaseSdp(mediaStreamList, excludeIceCandidates, waitForIceGatheringToComplete);

            int indexAudioStream = 0;
            int indexVideoStream = 0;
            _rtpExtensionsUsed ??= new Dictionary<string, int>();
            foreach (var ann in offerSdp.Media)
            {

                if (ann.Media == SDPMediaTypesEnum.audio)
                {
                    ann.HeaderExtensions.Clear();

                    var localHeaderExtensions = AudioStreamList[indexAudioStream].LocalTrack?.HeaderExtensions?.Values;
                    var remoteHeaderExtensions = AudioStreamList[indexAudioStream].RemoteTrack?.HeaderExtensions?.Values;

                    if (localHeaderExtensions?.Count > 0)
                    {

                        if (remoteHeaderExtensions is null || remoteHeaderExtensions.Count == 0)
                        {
                            foreach (var localExtension in localHeaderExtensions)
                            {

                                if (_rtpExtensionsUsed.ContainsKey(localExtension.Uri))
                                {
                                    localExtension.Id = _rtpExtensionsUsed[localExtension.Uri];
                                }
                                else
                                {
                                    _rtpExtensionsUsed[localExtension.Uri] = localExtension.Id;
                                }

                                logger.LogDebug("[createOffer] - {Media}:[{MediaID}] - Add HeaderExtensions:[{Id} - {Uri}]", ann.Media, ann.MediaID, localExtension.Id, localExtension.Uri);
                                ann.HeaderExtensions[localExtension.Id] = localExtension;
                            }
                        }
                        else
                        {
                            foreach (var remoteExtension in remoteHeaderExtensions)
                            {
                                var localExtension = localHeaderExtensions.FirstOrDefault(ext => ext.MatchesExtension(remoteExtension.Uri));
                                if ((localExtension != null) && _rtpExtensionsUsed.ContainsKey(remoteExtension.Uri))
                                {

                                    localExtension.Id = _rtpExtensionsUsed[remoteExtension.Uri];
                                    localExtension.Uri = remoteExtension.Uri;

                                    logger.LogDebug("[createOffer] - {Media}:[{MediaID}] - Add HeaderExtensions:[{Id} - {Uri}]", ann.Media, ann.MediaID, localExtension.Id, localExtension.Uri);
                                    ann.HeaderExtensions.Add(localExtension.Id, localExtension);
                                }
                            }
                        }
                    }
                    indexAudioStream++;
                }

                else if (ann.Media == SDPMediaTypesEnum.video)
                {
                    ann.HeaderExtensions.Clear();

                    var localHeaderExtensions = VideoStreamList[indexVideoStream].LocalTrack?.HeaderExtensions?.Values;
                    var remoteHeaderExtensions = VideoStreamList[indexVideoStream].RemoteTrack?.HeaderExtensions?.Values;
                    if (localHeaderExtensions?.Count > 0)
                    {

                        if (remoteHeaderExtensions is null || remoteHeaderExtensions.Count == 0)
                        {
                            foreach (var localExtension in localHeaderExtensions)
                            {

                                if (_rtpExtensionsUsed.ContainsKey(localExtension.Uri))
                                {
                                    localExtension.Id = _rtpExtensionsUsed[localExtension.Uri];
                                }
                                else
                                {
                                    _rtpExtensionsUsed[localExtension.Uri] = localExtension.Id;
                                }

                                logger.LogDebug("[createOffer] - {Media}:[{MediaID}] - Add HeaderExtensions:[{Id} - {Uri}]", ann.Media, ann.MediaID, localExtension.Id, localExtension.Uri);
                                ann.HeaderExtensions[localExtension.Id] = localExtension;
                            }
                        }
                        else
                        {
                            foreach (var remoteExtension in remoteHeaderExtensions)
                            {
                                var localExtension = localHeaderExtensions.FirstOrDefault(ext => ext.MatchesExtension(remoteExtension.Uri));
                                if ((localExtension != null) && _rtpExtensionsUsed.ContainsKey(remoteExtension.Uri))
                                {

                                    localExtension.Id = _rtpExtensionsUsed[remoteExtension.Uri];
                                    localExtension.Uri = remoteExtension.Uri;

                                    logger.LogDebug("[createOffer] - {Media}:[{MediaID}] - Add HeaderExtensions:[{Id} - {Uri}]", ann.Media, ann.MediaID, localExtension.Id, localExtension.Uri);
                                    ann.HeaderExtensions.Add(localExtension.Id, localExtension);
                                }
                            }
                        }
                    }
                    indexVideoStream++;
                }
                ann.IceRole = IceRole;
            }

            RTCSessionDescriptionInit initDescription = new RTCSessionDescriptionInit
            {
                type = RTCSdpType.offer,
                sdp = offerSdp.ToString()
            };

            return initDescription;
        }







        public override SDP CreateOffer(IPAddress connectionAddress)
        {
            var result = createOffer(null);

            if (result?.sdp != null)
            {
                return SDP.ParseSDPDescription(result.sdp);
            }

            return null;
        }







        public override SDP CreateAnswer(IPAddress connectionAddress)
        {
            var result = createAnswer(null);

            if (result?.sdp != null)
            {
                return SDP.ParseSDPDescription(result.sdp);
            }

            return null;
        }










        public RTCSessionDescriptionInit createAnswer(RTCAnswerOptions options = null)
        {
            if (remoteDescription == null)
            {
                throw new ApplicationException("The remote SDP must be set before an SDP answer can be created.");
            }
            else
            {
                List<MediaStream> mediaStreamList = GetMediaStreams();

                foreach (var mediaStream in mediaStreamList)
                {
                    if (mediaStream.LocalTrack != null && mediaStream.LocalTrack.StreamStatus == MediaStreamStatusEnum.Inactive)
                    {
                        mediaStream.LocalTrack.StreamStatus = mediaStream.LocalTrack.DefaultStreamStatus;
                    }
                }

                bool excludeIceCandidates = options != null && options.X_ExcludeIceCandidates;
                bool waitForIceGatheringToComplete = options != null && options.X_WaitForIceGatheringToComplete;
                var answerSdp = createBaseSdp(mediaStreamList, excludeIceCandidates, waitForIceGatheringToComplete);

                int indexAudioStream = 0;
                int indexVideoStream = 0;
                _rtpExtensionsUsed ??= new Dictionary<string, int>();
                foreach (var ann in answerSdp.Media)
                {

                    if (ann.Media == SDPMediaTypesEnum.audio)
                    {
                        ann.HeaderExtensions.Clear();

                        var localHeaderExtensions = AudioStreamList[indexAudioStream].LocalTrack?.HeaderExtensions?.Values;
                        var remoteHeaderExtensions = AudioStreamList[indexAudioStream].RemoteTrack?.HeaderExtensions?.Values;
                        if ((remoteHeaderExtensions?.Count > 0) && (localHeaderExtensions?.Count > 0))
                        {
                            foreach (var remoteExtension in remoteHeaderExtensions)
                            {
                                var localExtension = localHeaderExtensions.FirstOrDefault(ext => ext.MatchesExtension(remoteExtension.Uri));
                                if ((localExtension != null) && _rtpExtensionsUsed.ContainsKey(remoteExtension.Uri))
                                {

                                    localExtension.Id = _rtpExtensionsUsed[remoteExtension.Uri];
                                    localExtension.Uri = remoteExtension.Uri;

                                    logger.LogDebug("[createAnswer] - {Media}:[{MediaID}] - Add HeaderExtensions:[{Id} - {Uri}]", ann.Media, ann.MediaID, localExtension.Id, localExtension.Uri);
                                    ann.HeaderExtensions.Add(localExtension.Id, localExtension);
                                }
                            }
                        }
                        indexAudioStream++;
                    }

                    else if (ann.Media == SDPMediaTypesEnum.video)
                    {
                        ann.HeaderExtensions.Clear();

                        var localHeaderExtensions = VideoStreamList[indexVideoStream].LocalTrack?.HeaderExtensions?.Values;
                        var remoteHeaderExtensions = VideoStreamList[indexVideoStream].RemoteTrack?.HeaderExtensions?.Values;
                        if ((remoteHeaderExtensions?.Count > 0) && (localHeaderExtensions?.Count > 0))
                        {
                            foreach (var remoteExtension in remoteHeaderExtensions)
                            {
                                var localExtension = localHeaderExtensions.FirstOrDefault(ext => ext.MatchesExtension(remoteExtension.Uri));
                                if ((localExtension != null) && _rtpExtensionsUsed.ContainsKey(remoteExtension.Uri))
                                {

                                    localExtension.Id = _rtpExtensionsUsed[remoteExtension.Uri];
                                    localExtension.Uri = remoteExtension.Uri;

                                    logger.LogDebug("[createAnswer] - {Media}:[{MediaID}] - Add HeaderExtensions:[{Id} - {Uri}]", ann.Media, ann.MediaID, localExtension.Id, localExtension.Uri);
                                    ann.HeaderExtensions.Add(localExtension.Id, localExtension);
                                }
                            }
                        }
                        indexVideoStream++;
                    }
                }




                var answerRole = (IceRole == IceRolesEnum.active)
                    ? IceRolesEnum.active
                    : IceRolesEnum.passive;

                foreach (var ann in answerSdp.Media)
                {
                    ann.IceRole = answerRole;
                }

                RTCSessionDescriptionInit initDescription = new RTCSessionDescriptionInit
                {
                    type = RTCSdpType.answer,
                    sdp = answerSdp.ToString()
                };

                return initDescription;
            }
        }








        public void SetRemoteCredentials(string remoteIceUser, string remoteIcePassword)
        {
            _rtpIceChannel.SetRemoteCredentials(remoteIceUser, remoteIcePassword);
        }






        public RtpIceChannel GetRtpChannel()
        {
            return PrimaryStream.GetRTPChannel() as RtpIceChannel;
        }

















        private SDP createBaseSdp(List<MediaStream> mediaStreamList, bool excludeIceCandidates = false, bool waitForIceGatheringToComplete = false)
        {






            using (var ct = new CancellationTokenSource(TimeSpan.FromMilliseconds(_configuration.X_GatherTimeoutMs)))
            {
                try
                {
                    _iceInitiateGatheringTask.Wait(ct.Token);
                }
                catch (OperationCanceledException)
                {
                    logger.LogWarning("ICE gathering timed out after {GatherTimeoutMs}ms", _configuration.X_GatherTimeoutMs);
                }
            }

            if (waitForIceGatheringToComplete)
            {
                using (var ct = new CancellationTokenSource(TimeSpan.FromMilliseconds(_configuration.X_GatherTimeoutMs)))
                {
                    try
                    {
                        _iceCompletedGatheringTask.Task.Wait();
                    }
                    catch (OperationCanceledException)
                    {
                        logger.LogWarning("Waiting for ICE gathering to complete timed out after {GatherTimeoutMs}ms", _configuration.X_GatherTimeoutMs);
                    }
                }
            }

            SDP offerSdp = new SDP(IPAddress.Loopback);
            offerSdp.SessionId = LocalSdpSessionID;

            string dtlsFingerprint = this.DtlsCertificateFingerprint.ToString();
            bool iceCandidatesAdded = false;


            void AddIceCandidates(SDPMediaAnnouncement announcement)
            {
                if (_rtpIceChannel.Candidates?.Count > 0)
                {
                    announcement.IceCandidates = new List<string>();


                    foreach (var iceCandidate in _rtpIceChannel.Candidates)
                    {
                        announcement.IceCandidates.Add(iceCandidate.ToString());
                    }

                    foreach (var iceCandidate in _applicationIceCandidates)
                    {
                        announcement.IceCandidates.Add(iceCandidate.ToString());
                    }

                    if (_rtpIceChannel.IceGatheringState == RTCIceGatheringState.complete)
                    {
                        announcement.AddExtra($"a={SDP.END_ICE_CANDIDATES_ATTRIBUTE}");
                    }
                }
            };





            int mediaIndex = 0;
            int audioMediaIndex = 0;
            int videoMediaIndex = 0;
            int nextNewMLineIndex = RemoteDescription?.Media.Count ?? 0;
            foreach (var mediaStream in mediaStreamList)
            {
                int mindex = 0;
                string midTag = "0";

                if (RemoteDescription == null)
                {
                    mindex = mediaIndex;
                    midTag = mediaIndex.ToString();
                }
                else
                {
                    if (mediaStream.LocalTrack.Kind == SDPMediaTypesEnum.audio)
                    {
                        (mindex, midTag) = RemoteDescription.GetIndexForMediaType(mediaStream.LocalTrack.Kind, audioMediaIndex);
                        audioMediaIndex++;
                    }
                    else if (mediaStream.LocalTrack.Kind == SDPMediaTypesEnum.video)
                    {
                        (mindex, midTag) = RemoteDescription.GetIndexForMediaType(mediaStream.LocalTrack.Kind, videoMediaIndex);
                        videoMediaIndex++;
                    }
                }
                mediaIndex++;

                if (mindex == SDP.MEDIA_INDEX_NOT_PRESENT)
                {



                    mindex = nextNewMLineIndex;
                    midTag = nextNewMLineIndex.ToString();
                    nextNewMLineIndex++;
                }

                {
                    SDPMediaAnnouncement announcement = new SDPMediaAnnouncement(
                     mediaStream.LocalTrack.Kind,
                     SDP.IGNORE_RTP_PORT_NUMBER,
                     mediaStream.LocalTrack.Capabilities);

                    announcement.Transport = RTP_MEDIA_PROFILE;
                    announcement.Connection = new SDPConnectionInformation(IPAddress.Any);
                    announcement.AddExtra(RTCP_MUX_ATTRIBUTE);
                    announcement.AddExtra(RTCP_ATTRIBUTE);
                    announcement.MediaStreamStatus = mediaStream.LocalTrack.StreamStatus;
                    announcement.MediaID = midTag;
                    announcement.MLineIndex = mindex;

                    announcement.IceUfrag = _rtpIceChannel.LocalIceUser;
                    announcement.IcePwd = _rtpIceChannel.LocalIcePassword;
                    announcement.IceOptions = ICE_OPTIONS;
                    announcement.IceRole = IceRole;
                    announcement.DtlsFingerprint = dtlsFingerprint;

                    if (iceCandidatesAdded == false && !excludeIceCandidates)
                    {
                        AddIceCandidates(announcement);
                        iceCandidatesAdded = true;
                    }

                    if (mediaStream.LocalTrack.Ssrc != 0)
                    {
                        string trackCname = mediaStream.RtcpSession?.Cname;

                        if (trackCname != null)
                        {
                            announcement.SsrcAttributes.Add(new SDPSsrcAttribute(mediaStream.LocalTrack.Ssrc, trackCname, null));
                        }
                    }

                    offerSdp.Media.Add(announcement);
                }
            }

            if (DataChannels.Count > 0 || (RemoteDescription?.Media.Any(x => x.Media == SDPMediaTypesEnum.application) ?? false))
            {
                (int mindex, string midTag) = RemoteDescription == null ? (mediaIndex, mediaIndex.ToString()) : RemoteDescription.GetIndexForMediaType(SDPMediaTypesEnum.application, 0);
                mediaIndex++;

                if (mindex == SDP.MEDIA_INDEX_NOT_PRESENT)
                {
                    logger.LogWarning("Media announcement for data channel establishment omitted due to no reciprocal remote announcement.");
                }
                else
                {
                    SDPMediaAnnouncement dataChannelAnnouncement = new SDPMediaAnnouncement(
                        SDPMediaTypesEnum.application,
                        SDP.IGNORE_RTP_PORT_NUMBER,
                        new List<SDPApplicationMediaFormat> { new SDPApplicationMediaFormat(SDP_DATACHANNEL_FORMAT_ID) });
                    dataChannelAnnouncement.Transport = RTP_MEDIA_DATACHANNEL_UDPDTLS_PROFILE;
                    dataChannelAnnouncement.Connection = new SDPConnectionInformation(IPAddress.Any);

                    dataChannelAnnouncement.SctpPort = SCTP_DEFAULT_PORT;
                    dataChannelAnnouncement.MaxMessageSize = sctp.maxMessageSize;
                    dataChannelAnnouncement.MLineIndex = mindex;
                    dataChannelAnnouncement.MediaID = midTag;
                    dataChannelAnnouncement.IceUfrag = _rtpIceChannel.LocalIceUser;
                    dataChannelAnnouncement.IcePwd = _rtpIceChannel.LocalIcePassword;
                    dataChannelAnnouncement.IceOptions = ICE_OPTIONS;
                    dataChannelAnnouncement.IceRole = IceRole;
                    dataChannelAnnouncement.DtlsFingerprint = dtlsFingerprint;

                    if (iceCandidatesAdded == false && !excludeIceCandidates)
                    {
                        AddIceCandidates(dataChannelAnnouncement);
                        iceCandidatesAdded = true;
                    }

                    offerSdp.Media.Add(dataChannelAnnouncement);
                }
            }


            if (offerSdp.Media?.Count > 0)
            {
                offerSdp.Group = BUNDLE_ATTRIBUTE;
                foreach (var ann in offerSdp.Media.OrderBy(x => x.MLineIndex).ThenBy(x => x.MediaID))
                {
                    offerSdp.Group += $" {ann.MediaID}";
                }
            }

            return offerSdp;
        }















        private void OnRTPDataReceived(int localPort, IPEndPoint remoteEP, byte[] buffer)
        {







            if (buffer?.Length > 0)
            {









                if (!(_rtpIceChannel?.IsKnownRemoteEndPoint(remoteEP) ?? false))
                {
                    if (logger.IsEnabled(Microsoft.Extensions.Logging.LogLevel.Debug))
                    {
                        logger.LogDebug(
                            "Dropped {ByteCount} byte non-STUN packet from {RemoteEndPoint}; source does not match any known ICE remote candidate (issues #1559, #1731).",
                            buffer.Length, remoteEP);
                    }
                    return;
                }

                try
                {
                    if (buffer?.Length > RTPHeader.MIN_HEADER_LEN && buffer[0] >= 128 && buffer[0] <= 191)
                    {

                        base.OnReceive(localPort, remoteEP, buffer);
                    }
                    else
                    {
                        if (_dtlsHandle != null)
                        {

                            _dtlsHandle.WriteToRecvStream(buffer);
                        }
                        else
                        {
                            logger.LogWarning("DTLS packet received {BufferLength} bytes from {RemoteEndPoint} but no DTLS transport available.", buffer.Length, remoteEP);
                        }
                    }
                }
                catch (Exception excp)
                {
                    logger.LogError(excp, "Exception RTCPeerConnection.OnRTPDataReceived {ErrorMessage}", excp.Message);
                }
            }
        }


        private Func<IPEndPoint, IPEndPoint> _remoteEndpointTranslator;
















        public Func<IPEndPoint, IPEndPoint> RemoteEndpointTranslator
        {
            get => _remoteEndpointTranslator;
            set
            {
                _remoteEndpointTranslator = value;
                if (_rtpIceChannel != null)
                {
                    _rtpIceChannel.RemoteEndpointTranslator = value;
                }
            }
        }












        public void addLocalIceCandidate(RTCIceCandidate candidate)
        {
            candidate.usernameFragment = _rtpIceChannel.LocalIceUser;
            _applicationIceCandidates.Add(candidate);
        }





        public void addIceCandidate(RTCIceCandidateInit candidateInit)
        {
            RTCIceCandidate candidate = new RTCIceCandidate(candidateInit);

            if (_rtpIceChannel.Component == candidate.component)
            {
                _rtpIceChannel.AddRemoteCandidate(candidate);
            }
            else
            {
                logger.LogWarning("Remote ICE candidate not added as no available ICE session for component {Component}.", candidate.component);
            }
        }




        public void restartIce()
        {
            _rtpIceChannel.Restart();
        }






        public RTCConfiguration getConfiguration()
        {
            return _configuration;
        }





        public void setConfiguration(RTCConfiguration configuration = null)
        {
            throw new NotImplementedException();
        }





        private void UpdatedSctpDestinationPort()
        {

            var sctpAnn = RemoteDescription.Media.Where(x => x.Media == SDPMediaTypesEnum.application).FirstOrDefault();
            ushort destinationPort = sctpAnn?.SctpPort != null ? sctpAnn.SctpPort.Value : SCTP_DEFAULT_PORT;

            if (destinationPort != SCTP_DEFAULT_PORT)
            {
                sctp.UpdateDestinationPort(destinationPort);
            }
        }





        protected virtual Task StartOnNegotiationNeededTask()
        {
            const int RENEGOTIATION_CALL_DELAY = 100;


            CancelOnNegotiationNeededTask();

            CancellationToken token;
            lock (_renegotiationLock)
            {
                _cancellationSource = new CancellationTokenSource();
                token = _cancellationSource.Token;
            }
            return Task.Run(async () =>
            {
                try
                {

                    await Task.Delay(RENEGOTIATION_CALL_DELAY, token);
                }
                catch (TaskCanceledException)
                {
                }


                if (token.IsCancellationRequested)
                {
                    return;
                }
                else
                {
                    if (_requireRenegotiation)
                    {

                        onnegotiationneeded?.Invoke();
                    }
                }
            }, token);
        }




        protected virtual void CancelOnNegotiationNeededTask()
        {
            lock (_renegotiationLock)
            {
                if (_cancellationSource != null)
                {
                    if (!_cancellationSource.IsCancellationRequested)
                    {
                        _cancellationSource.Cancel();
                    }

                    _cancellationSource.Dispose();
                    _cancellationSource = null;
                }
            }
        }







        private async Task InitialiseSctpTransport()
        {
            try
            {
                sctp.OnStateChanged += OnSctpTransportStateChanged;
                sctp.Start(_dtlsHandle.Transport, _dtlsHandle.IsClient);

                if (DataChannels.Count > 0)
                {
                    await InitialiseSctpAssociation().ConfigureAwait(false);
                }
            }
            catch (Exception excp)
            {
                logger.LogError(excp, "SCTP exception establishing association, data channels will not be available. {ErrorMessage}", excp.Message);
                sctp?.Close();
            }
        }





        private void OnSctpTransportStateChanged(RTCSctpTransportState state)
        {
            if (state == RTCSctpTransportState.Connected)
            {
                logger.LogDebug("SCTP transport successfully connected.");

                sctp.RTCSctpAssociation.OnDataChannelData += OnSctpAssociationDataChunk;
                sctp.RTCSctpAssociation.OnDataChannelOpened += OnSctpAssociationDataChannelOpened;
                sctp.RTCSctpAssociation.OnNewDataChannel += OnSctpAssociationNewDataChannel;


                foreach (var dataChannel in _dataChannels.ActivatePendingChannels())
                {
                    OpenDataChannel(dataChannel);
                }
            }
        }




        private void OnSctpAssociationNewDataChannel(ushort streamID, DataChannelTypes type, ushort priority, uint reliability, string label, string protocol)
        {
            logger.LogInformation("WebRTC new data channel opened by remote peer for stream ID {StreamID}, type {Type}, priority {Priority}, reliability {Reliability}, label {Label}, protocol {Protocol}.",
                streamID, type, priority, reliability, label, protocol);


            var dc = new RTCDataChannel(sctp)
            {
                id = streamID,
                label = label,
                IsOpened = true,
                readyState = RTCDataChannelState.open,
                protocol = protocol
            };

            dc.SendDcepAck();

            if (_dataChannels.AddActiveChannel(dc))
            {
                ondatachannel?.Invoke(dc);
            }
            else
            {

                logger.LogWarning("WebRTC duplicate data channel requested for stream ID {StreamID}.", streamID);
            }
        }





        private void OnSctpAssociationDataChannelOpened(ushort streamID)
        {
            _dataChannels.TryGetChannel(streamID, out var dc);

            string label = dc != null ? dc.label : "<none>";
            logger.LogDebug("WebRTC data channel opened label {Label} and stream ID {StreamID}.", label, streamID);

            if (dc != null)
            {
                dc.GotAck();
            }
            else
            {
                logger.LogWarning("WebRTC data channel got ACK but data channel not found for stream ID {StreamID}.", streamID);
            }
        }




        private void OnSctpAssociationDataChunk(SctpDataFrame frame)
        {
            if (_dataChannels.TryGetChannel(frame.StreamID, out var dc))
            {
                dc.GotData(frame.StreamID, frame.StreamSeqNum, frame.PPID, frame.UserData);
            }
            else
            {
                logger.LogWarning("WebRTC data channel got data but no channel found for stream ID {StreamID}.", frame.StreamID);
            }
        }





        private async Task InitialiseSctpAssociation()
        {
            if (sctp.RTCSctpAssociation.State != SctpAssociationState.Established)
            {
                sctp.Associate();
            }

            if (sctp.state != RTCSctpTransportState.Connected)
            {
                TaskCompletionSource<bool> onSctpConnectedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                sctp.OnStateChanged += (state) =>
                {
                    logger.LogDebug("SCTP transport for create data channel request changed to state {State}.", state);

                    if (state == RTCSctpTransportState.Connected)
                    {
                        onSctpConnectedTcs.TrySetResult(true);
                    }
                };

                DateTime startTime = DateTime.Now;

                var completedTask = await Task.WhenAny(onSctpConnectedTcs.Task, Task.Delay(SCTP_ASSOCIATE_TIMEOUT_SECONDS * 1000)).ConfigureAwait(false);

                if (sctp.state != RTCSctpTransportState.Connected)
                {
                    var duration = DateTime.Now.Subtract(startTime).TotalMilliseconds;

                    if (completedTask != onSctpConnectedTcs.Task)
                    {
                        throw new ApplicationException($"SCTP association timed out after {duration:0.##}ms with association in state {sctp.RTCSctpAssociation.State} when attempting to create a data channel.");
                    }
                    else
                    {
                        throw new ApplicationException($"SCTP association failed after {duration:0.##}ms with association in state {sctp.RTCSctpAssociation.State} when attempting to create a data channel.");
                    }
                }
            }
        }










        public async Task<RTCDataChannel> createDataChannel(string label, RTCDataChannelInit init = null)
        {
            logger.LogDebug("Data channel create request for label {Label}.", label);

            RTCDataChannel channel = new RTCDataChannel(sctp, init)
            {
                label = label,
            };

            if (connectionState == RTCPeerConnectionState.connected)
            {




                if (sctp == null || sctp.state != RTCSctpTransportState.Connected)
                {
                    throw new ApplicationException("No SCTP transport is available.");
                }
                else
                {
                    if (sctp.RTCSctpAssociation == null ||
                        sctp.RTCSctpAssociation.State != SctpAssociationState.Established)
                    {
                        await InitialiseSctpAssociation().ConfigureAwait(false);
                    }

                    _dataChannels.AddActiveChannel(channel);
                    OpenDataChannel(channel);


                    TaskCompletionSource<string> isopen = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                    channel.onopen += () => isopen.TrySetResult(string.Empty);
                    channel.onerror += (err) => isopen.TrySetResult(err);
                    var error = await isopen.Task.ConfigureAwait(false);

                    if (error != string.Empty)
                    {
                        throw new ApplicationException($"Data channel creation failed with: {error}");
                    }
                    else
                    {
                        return channel;
                    }
                }
            }
            else
            {



                _dataChannels.AddPendingChannel(channel);
                return channel;
            }
        }






        private void OpenDataChannel(RTCDataChannel dataChannel)
        {
            if (dataChannel.negotiated)
            {
                logger.LogDebug("WebRTC data channel negotiated out of band with label {Label} and stream ID {StreamID}; invoking open event", dataChannel.label, dataChannel.id);
                dataChannel.GotAck();
            }
            else if (dataChannel.id.HasValue)
            {
                logger.LogDebug("WebRTC attempting to open data channel with label {Label} and stream ID {StreamID}.", dataChannel.label, dataChannel.id);
                dataChannel.SendDcepOpen();
            }
            else
            {
                logger.LogError("Attempt to open a data channel without an assigned ID has failed.");
            }
        }









        private bool DoDtlsHandshake(DtlsSrtpTransport dtlsHandle)
        {
            logger.LogDebug("RTCPeerConnection DoDtlsHandshake started.");

            var rtpChannel = PrimaryStream.GetRTPChannel();

            dtlsHandle.OnDataReady += (buf) =>
            {

                rtpChannel.Send(RTPChannelSocketsEnum.RTP, PrimaryStream.DestinationEndPoint, buf);
            };

            var handshakeResult = dtlsHandle.DoHandshake(out var handshakeError);

            if (!handshakeResult)
            {
                handshakeError = handshakeError ?? "unknown";
                logger.LogWarning("RTCPeerConnection DTLS handshake failed with error {HandshakeError}.", handshakeError);
                Close("dtls handshake failed");
                return false;
            }
            else
            {
                logger.LogDebug("RTCPeerConnection DTLS handshake result {HandshakeResult}, is handshake complete {IsHandshakeComplete}.",
                    handshakeResult, dtlsHandle.IsHandshakeComplete());

                var expectedFp = RemotePeerDtlsFingerprint;
                var remoteFingerprint = DtlsUtils.Fingerprint(expectedFp.algorithm, dtlsHandle.GetRemoteCertificate().GetCertificateAt(0));

                if (!string.Equals(remoteFingerprint.value, expectedFp.value, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogWarning("RTCPeerConnection remote certificate fingerprint mismatch, expected {ExpectedFingerprint}, actual {RemoteFingerprint}.", expectedFp, remoteFingerprint);
                    Close("dtls fingerprint mismatch");
                    return false;
                }
                else
                {
                    logger.LogDebug("RTCPeerConnection remote certificate fingerprint matched expected value of {RemoteFingerprintValue} for {RemoteFingerprintAlgorithm}.", remoteFingerprint.value, remoteFingerprint.algorithm);

                    SetGlobalSecurityContext(dtlsHandle.ProtectRTP,
                        dtlsHandle.UnprotectRTP,
                        dtlsHandle.ProtectRTCP,
                        dtlsHandle.UnprotectRTCP);


                    IsDtlsNegotiationComplete = true;

                    return true;
                }
            }
        }







        private void OnDtlsAlert(TlsAlertLevelsEnum alertLevel, TlsAlertTypesEnum alertType, string alertDescription)
        {
            if (alertType == TlsAlertTypesEnum.CloseNotify)
            {
                logger.LogDebug("Closing peer connection as a result of DTLS close notification.");
















                Close("Remote DTLS close notification received");
            }
            else
            {
                string alertMsg = !string.IsNullOrEmpty(alertDescription) ? $": {alertDescription}" : ".";
                logger.LogWarning("DTLS unexpected {AlertLevel} alert {AlertType}{AlertMsg}", alertLevel, alertType, alertMsg);
            }
        }




        protected override void Dispose(bool disposing)
        {
            Close("disposed");
        }




        public override void Dispose()
        {
            Close("disposed");
        }
    }
}
