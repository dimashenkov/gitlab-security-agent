
















using System;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public enum RTCSctpTransportState
    {
        Connecting,
        Connected,
        Closed
    };











    public class RTCSctpTransport : SctpTransport
    {
        private const string THREAD_NAME_PREFIX = "rtcsctprecv-";





        private const int RECEIVE_TIMEOUT_MILLISECONDS = 1000;







        internal const uint SCTP_DEFAULT_MAX_MESSAGE_SIZE = 262144;

        private static readonly ILogger logger = LogFactory.CreateLogger<RTCSctpTransport>();





        public override bool IsPortAgnostic => true;





        public DatagramTransport transport { get; private set; }





        public bool IsDtlsClient { get; private set; }




        public RTCSctpTransportState state { get; private set; }







        public uint maxMessageSize => SCTP_DEFAULT_MAX_MESSAGE_SIZE;





        public readonly ushort maxChannels;

        public RTCPeerSctpAssociation RTCSctpAssociation { get; private set; }




        public event Action<RTCSctpTransportState> OnStateChanged;

        private bool _isStarted;
        private volatile bool _isClosed;
        private Thread _receiveThread;
        private readonly object _lock = new object();








        public RTCSctpTransport(ushort sourcePort, ushort destinationPort, int dtlsPort)
        {
            SetState(RTCSctpTransportState.Closed);

            RTCSctpAssociation = new RTCPeerSctpAssociation(this, sourcePort, destinationPort, dtlsPort);
            RTCSctpAssociation.OnAssociationStateChanged += OnAssociationStateChanged;
        }





        public void UpdateSourcePort(ushort port)
        {
            if (state != RTCSctpTransportState.Closed)
            {
                logger.LogWarning("SCTP source port cannot be updated when the transport is in state {State}.", state);
            }
            else
            {
                RTCSctpAssociation.UpdateSourcePort(port);
            }
        }





        public void UpdateDestinationPort(ushort port)
        {
            if (state != RTCSctpTransportState.Closed)
            {
                logger.LogWarning("SCTP destination port cannot be updated when the transport is in state {State}.", state);
            }
            else
            {
                RTCSctpAssociation.UpdateDestinationPort(port);
            }
        }




        public void Start(DatagramTransport dtlsTransport, bool isDtlsClient)
        {
            if (!_isStarted)
            {
                _isStarted = true;

                transport = dtlsTransport;
                IsDtlsClient = isDtlsClient;

                _receiveThread = new Thread(DoReceive);
                _receiveThread.Name = $"{THREAD_NAME_PREFIX}{RTCSctpAssociation.ID}";
                _receiveThread.IsBackground = true;
                _receiveThread.Start();
            }
        }




        public void Associate()
        {
            SetState(RTCSctpTransportState.Connecting);
            RTCSctpAssociation.Init();
        }




        public void Close()
        {
            lock (_lock)
            {
                if (!_isClosed)
                {
                    if (state == RTCSctpTransportState.Connected)
                    {
                        RTCSctpAssociation?.Shutdown();
                    }
                    else
                    {


                        RTCSctpAssociation?.Abort(new SctpErrorUserInitiatedAbort { AbortReason = "SCTP transport closing." });
                    }
                    _isClosed = true;
                }
            }
        }






        private void OnAssociationStateChanged(SctpAssociationState associationState)
        {
            if (associationState == SctpAssociationState.Established)
            {
                SetState(RTCSctpTransportState.Connected);
            }
            else if (associationState == SctpAssociationState.Closed)
            {
                SetState(RTCSctpTransportState.Closed);
            }
        }





        private void SetState(RTCSctpTransportState newState)
        {
            state = newState;
            OnStateChanged?.Invoke(state);
        }







        protected override SctpTransportCookie GetInitAckCookie(
            ushort sourcePort,
            ushort destinationPort,
            uint remoteTag,
            uint remoteTSN,
            uint remoteARwnd,
            string remoteEndPoint,
            int lifeTimeExtension = 0)
        {
            var cookie = new SctpTransportCookie
            {
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                RemoteTag = remoteTag,
                RemoteTSN = remoteTSN,
                RemoteARwnd = remoteARwnd,
                RemoteEndPoint = remoteEndPoint,
                Tag = RTCSctpAssociation.VerificationTag,
                TSN = RTCSctpAssociation.TSN,
                ARwnd = SctpAssociation.DEFAULT_ADVERTISED_RECEIVE_WINDOW,
                CreatedAt = DateTime.Now.ToString("o"),
                Lifetime = DEFAULT_COOKIE_LIFETIME_SECONDS + lifeTimeExtension,
                HMAC = string.Empty
            };

            return cookie;
        }





        private void DoReceive(object state)
        {
            byte[] recvBuffer = new byte[SctpAssociation.DEFAULT_ADVERTISED_RECEIVE_WINDOW];

            while (!_isClosed)
            {
                try
                {
                    int bytesRead = transport.Receive(recvBuffer, 0, recvBuffer.Length, RECEIVE_TIMEOUT_MILLISECONDS);

                    if (bytesRead == DtlsSrtpTransport.DTLS_RETRANSMISSION_CODE)
                    {


                        continue;
                    }
                    else if (bytesRead > 0)
                    {
                        if (!SctpPacket.VerifyChecksum(recvBuffer, 0, bytesRead))
                        {
                            logger.LogWarning("SCTP packet received on DTLS transport dropped due to invalid checksum.");
                        }
                        else
                        {
                            var pkt = SctpPacket.Parse(recvBuffer, 0, bytesRead);

                            if (pkt.Chunks.Any(x => x.KnownType == SctpChunkType.INIT))
                            {
                                var initChunk = pkt.Chunks.First(x => x.KnownType == SctpChunkType.INIT) as SctpInitChunk;
                                logger.LogDebug("SCTP INIT packet received, initial tag {InitiateTag}, initial TSN {InitialTSN}.", initChunk.InitiateTag, initChunk.InitialTSN);

                                GotInit(pkt, null);
                            }
                            else if (pkt.Chunks.Any(x => x.KnownType == SctpChunkType.COOKIE_ECHO))
                            {


                                var cookie = base.GetCookie(pkt);

                                if (cookie.IsEmpty())
                                {
                                    logger.LogWarning("SCTP error acquiring handshake cookie from COOKIE ECHO chunk.");
                                }
                                else
                                {
                                    RTCSctpAssociation.GotCookie(cookie);

                                    if (pkt.Chunks.Count() > 1)
                                    {

                                        RTCSctpAssociation.OnPacketReceived(pkt);
                                    }
                                }
                            }
                            else
                            {
                                RTCSctpAssociation.OnPacketReceived(pkt);
                            }
                        }
                    }
                    else if (_isClosed)
                    {

                        logger.LogWarning("SCTP the RTCSctpTransport DTLS transport returned an error.");
                        break;
                    }
                }
                catch (ApplicationException appExcp)
                {

                    logger.LogWarning("SCTP error processing RTCSctpTransport receive. {Message}", appExcp.Message);
                }
                catch (TlsFatalAlert alert) when (alert.InnerException is SocketException)
                {
                    var sockExcp = alert.InnerException as SocketException;
                    logger.LogWarning(sockExcp, "SCTP RTCSctpTransport receive socket failure {SocketErrorCode}.", sockExcp.SocketErrorCode);
                    break;
                }
                catch (Exception excp)
                {
                    logger.LogError(excp, "SCTP fatal error processing RTCSctpTransport receive. {ErrorMessage}", excp.Message);
                    break;
                }
            }

            if (!_isClosed)
            {
                logger.LogWarning("SCTP association {ID} receive thread stopped.", RTCSctpAssociation.ID);
            }

            SetState(RTCSctpTransportState.Closed);
        }









        public override void Send(string associationID, byte[] buffer, int offset, int length)
        {
            if (length > maxMessageSize)
            {
                throw new ApplicationException($"RTCSctpTransport was requested to send data of length {length}  that exceeded the maximum allowed message size of {maxMessageSize}.");
            }

            if (!_isClosed)
            {
                lock (_lock)
                {
                    if (!_isClosed)
                    {
                        transport.Send(buffer, offset, length);
                    }
                }
            }
        }
    }
}
