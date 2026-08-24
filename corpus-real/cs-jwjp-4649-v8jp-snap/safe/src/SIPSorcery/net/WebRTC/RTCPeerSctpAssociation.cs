
























using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public delegate void OnRTCDataChannelOpened(ushort streamID);

    public delegate void OnNewRTCDataChannel(ushort streamID, DataChannelTypes type, ushort priority, uint reliability, string label, string protocol);

    public class RTCPeerSctpAssociation : SctpAssociation
    {

        public const ushort DEFAULT_DTLS_MTU = 1200;

        private static readonly ILogger logger = LogFactory.CreateLogger<RTCPeerSctpAssociation>();




        private RTCSctpTransport _rtcSctpTransport;




        public event Action<SctpDataFrame> OnDataChannelData;





        public event OnRTCDataChannelOpened OnDataChannelOpened;




        public event OnNewRTCDataChannel OnNewDataChannel;










        public RTCPeerSctpAssociation(RTCSctpTransport rtcSctpTransport, ushort srcPort, ushort dstPort, int dtlsPort)
            : base(rtcSctpTransport, null, srcPort, dstPort, DEFAULT_DTLS_MTU, dtlsPort)
        {
            _rtcSctpTransport = rtcSctpTransport;
            logger.LogDebug("SCTP creating DTLS based association, is DTLS client {IsDtlsClient}, ID {ID}.", _rtcSctpTransport.IsDtlsClient, ID);

            OnData += OnDataFrameReceived;
        }







        private void OnDataFrameReceived(SctpDataFrame dataFrame)
        {
            switch (dataFrame)
            {
                case var frame when frame.PPID == (uint)DataChannelPayloadProtocols.WebRTC_DCEP:
                    switch (frame.UserData[0])
                    {
                        case (byte)DataChannelMessageTypes.ACK:
                            OnDataChannelOpened?.Invoke(frame.StreamID);
                            break;
                        case (byte)DataChannelMessageTypes.OPEN:
                            var dcepOpen = DataChannelOpenMessage.Parse(frame.UserData, 0);

                            logger.LogDebug("DCEP OPEN channel type {ChannelType}, priority {Priority}, reliability {Reliability}, label {Label}, protocol {Protocol}.",
                                dcepOpen.ChannelType, dcepOpen.Priority, dcepOpen.Reliability, dcepOpen.Label, dcepOpen.Protocol);

                            DataChannelTypes channelType = DataChannelTypes.DATA_CHANNEL_RELIABLE;
                            if(Enum.IsDefined(typeof(DataChannelTypes), dcepOpen.ChannelType))
                            {
                                channelType = (DataChannelTypes)dcepOpen.ChannelType;
                            }
                            else
                            {
                                logger.LogWarning("DECP OPEN channel type of {ChannelType} not recognised, defaulting to {DefaultChannelType}.", dcepOpen.ChannelType, channelType);
                            }

                            OnNewDataChannel?.Invoke(
                                frame.StreamID,
                                channelType,
                                dcepOpen.Priority,
                                dcepOpen.Reliability,
                                dcepOpen.Label,
                                dcepOpen.Protocol);

                            break;
                        default:
                            logger.LogWarning("DCEP message type {MessageType} not recognised, ignoring.", frame.UserData[0]);
                            break;
                    }
                    break;

                default:
                    OnDataChannelData?.Invoke(dataFrame);
                    break;
            }
        }
    }
}
