















using System;
using System.Text;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{







    public enum DataChannelPayloadProtocols : uint
    {
        WebRTC_DCEP = 50,
        WebRTC_String = 51,
        WebRTC_Binary_Partial = 52,
        WebRTC_Binary = 53,
        WebRTC_String_Partial = 54,
        WebRTC_String_Empty = 56,
        WebRTC_Binary_Empty = 57
    }






    public class RTCDataChannel : IRTCDataChannel
    {
        private static readonly ILogger logger = LogFactory.CreateLogger<RTCDataChannel>();

        public string label { get; set; }

        public bool ordered { get; set; }

        public ushort? maxPacketLifeTime { get; set; }

        public ushort? maxRetransmits { get; set; }

        public string protocol { get; set; }

        public bool negotiated { get; set; }

        public ushort? id { get; set; }

        public RTCDataChannelState readyState { get; internal set; } = RTCDataChannelState.connecting;

        public ulong bufferedAmount => _transport?.RTCSctpAssociation?.SendBufferedAmount ?? 0;

        public ulong bufferedAmountLowThreshold { get; set; }
        public string binaryType { get; set; }



        public string Error { get; private set; }

        public bool IsOpened { get; internal set; } = false;

        private RTCSctpTransport _transport;

        public event Action onopen;

        public event Action<string> onerror;

        public event Action onclose;
        public event OnDataChannelMessageDelegate onmessage;

        public RTCDataChannel(RTCSctpTransport transport, RTCDataChannelInit init = null)
        {
            _transport = transport;

            if (init == null) {
                ordered = true;
                return;
            }

            ordered = init.ordered ?? true;
            maxPacketLifeTime = init.maxPacketLifeTime;
            maxRetransmits = init.maxRetransmits;
            protocol = init.protocol ?? "";
            negotiated = init.negotiated ?? false;
            id = init.id;
        }

        internal void GotAck()
        {
            logger.LogDebug("Data channel for label {label} now open.", label);
            IsOpened = true;
            readyState = RTCDataChannelState.open;
            onopen?.Invoke();
        }




        internal void SetError(string error)
        {
            Error = error;
            onerror?.Invoke(error);
        }

        public void close()
        {
            IsOpened = false;
            readyState = RTCDataChannelState.closed;
            logger.LogDebug("Data channel with id {id} has been closed", id);
            onclose?.Invoke();
        }





        public void send(string message)
        {
            if (message != null && Encoding.UTF8.GetByteCount(message) > _transport.maxMessageSize)
            {
                throw new ApplicationException($"Data channel {label} was requested to send data of length {Encoding.UTF8.GetByteCount(message)} that exceeded the maximum allowed message size of {_transport.maxMessageSize}.");
            }
            else if (_transport.state != RTCSctpTransportState.Connected)
            {
                logger.LogWarning("WebRTC data channel send failed due to SCTP transport in state {TransportState}.", _transport.state);
            }
            else
            {
                lock (this)
                {
                    if (string.IsNullOrEmpty(message))
                    {
                        _transport.RTCSctpAssociation.SendData(id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_String_Empty,
                            new byte[] { 0x00 });
                    }
                    else
                    {
                        _transport.RTCSctpAssociation.SendData(id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_String,
                            Encoding.UTF8.GetBytes(message));
                    }
                }
            }
        }







        public void send(byte[] data, int offset = 0, int count = -1)
        {
            int effectiveCount = count < 0 ? data.Length - offset : count;

            if (effectiveCount > _transport.maxMessageSize)
            {
                throw new ApplicationException($"Data channel {label} was requested to send data of length {effectiveCount} that exceeded the maximum allowed message size of {_transport.maxMessageSize}.");
            }
            else if (_transport.state != RTCSctpTransportState.Connected)
            {
                logger.LogWarning("WebRTC data channel send failed due to SCTP transport in state {TransportState}.", _transport.state);
            }
            else
            {
                lock (this)
                {
                    if (effectiveCount == 0)
                    {
                        _transport.RTCSctpAssociation.SendData(id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_Binary_Empty,
                            new byte[] { 0x00 });
                    }
                    else
                    {
                        _transport.RTCSctpAssociation.SendData(id.GetValueOrDefault(),
                            (uint)DataChannelPayloadProtocols.WebRTC_Binary,
                            data, offset, effectiveCount);
                    }
                }
            }
        }





        internal void SendDcepOpen()
        {
            byte type = (byte)DataChannelTypes.DATA_CHANNEL_RELIABLE;
            if (!ordered)
            {
                type += (byte)DataChannelTypes.DATA_CHANNEL_RELIABLE_UNORDERED;
            }
            if (maxPacketLifeTime > 0)
            {
                type += (byte)DataChannelTypes.DATA_CHANNEL_PARTIAL_RELIABLE_TIMED;
            }
            else if(maxRetransmits > 0)
            {
                type += (byte)DataChannelTypes.DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT;
            }

            var dcepOpen = new DataChannelOpenMessage()
            {
                MessageType = (byte)DataChannelMessageTypes.OPEN,
                ChannelType = (byte)type,
                Label = label,
                Protocol = protocol,
            };

            lock (this)
            {
                _transport.RTCSctpAssociation.SendData(id.GetValueOrDefault(),
                       (uint)DataChannelPayloadProtocols.WebRTC_DCEP,
                       dcepOpen.GetBytes());
            }
        }





        internal void SendDcepAck()
        {
            lock (this)
            {
                _transport.RTCSctpAssociation.SendData(id.GetValueOrDefault(),
                       (uint)DataChannelPayloadProtocols.WebRTC_DCEP,
                       new byte[] { (byte)DataChannelMessageTypes.ACK });
            }
        }




        internal void GotData(ushort streamID, ushort streamSeqNum, uint ppID, byte[] data)
        {



            DataChannelPayloadProtocols payloadType = DataChannelPayloadProtocols.WebRTC_Binary;

            if (Enum.IsDefined(typeof(DataChannelPayloadProtocols), ppID))
            {
                payloadType = (DataChannelPayloadProtocols)ppID;
            }

            onmessage?.Invoke(this, (DataChannelPayloadProtocols)ppID, data);
        }
    }
}
