

























using System;
using System.Collections.Generic;
using System.Text;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public enum DataChannelMessageTypes : byte
    {
        ACK = 0x02,
        OPEN = 0x03,
    }

    public enum DataChannelTypes : byte
    {



        DATA_CHANNEL_RELIABLE = 0x00,






        DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT = 0x01,








        DATA_CHANNEL_PARTIAL_RELIABLE_TIMED = 0x02,




        DATA_CHANNEL_RELIABLE_UNORDERED = 0x80,






        DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED = 0x81,








        DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED = 0x82
    }









    public struct DataChannelOpenMessage
    {
        public const int DCEP_OPEN_FIXED_PARAMETERS_LENGTH = 12;





        public byte MessageType; 





        public byte ChannelType;




        public ushort Priority;




        public uint Reliability;




        public string Label;









        public string Protocol;







        public static DataChannelOpenMessage Parse(byte[] buffer, int posn)
        {
            if (buffer.Length < DCEP_OPEN_FIXED_PARAMETERS_LENGTH)
            {
                throw new ApplicationException("The buffer did not contain the minimum number of bytes for a DCEP open message.");
            }

            var dcepOpen = new DataChannelOpenMessage();

            dcepOpen.MessageType = buffer[posn];
            dcepOpen.ChannelType = buffer[posn + 1];
            dcepOpen.Priority = NetConvert.ParseUInt16(buffer, posn + 2);
            dcepOpen.Reliability = NetConvert.ParseUInt32(buffer, posn + 4);

            ushort labelLength = NetConvert.ParseUInt16(buffer, posn + 8);
            ushort protocolLength = NetConvert.ParseUInt16(buffer, posn + 10);

            if (labelLength > 0)
            {
                dcepOpen.Label = Encoding.UTF8.GetString(buffer, 12, labelLength);
            }

            if (protocolLength > 0)
            {
                dcepOpen.Protocol = Encoding.UTF8.GetString(buffer, 12 + labelLength, protocolLength);
            }

            return dcepOpen;
        }





        public int GetLength()
        {
            ushort labelLength = (ushort)(Label != null ? Encoding.UTF8.GetByteCount(Label) : 0);
            ushort protocolLength = (ushort)(Protocol != null ? Encoding.UTF8.GetByteCount(Protocol) : 0);

            return DCEP_OPEN_FIXED_PARAMETERS_LENGTH + labelLength + protocolLength;
        }









        public ushort WriteTo(byte[] buffer, int posn)
        {
            buffer[posn] = MessageType;
            buffer[posn + 1] = ChannelType;
            NetConvert.ToBuffer(Priority, buffer, posn + 2);
            NetConvert.ToBuffer(Reliability, buffer, posn + 4);

            ushort labelLength = (ushort)(Label != null ? Encoding.UTF8.GetByteCount(Label) : 0);
            ushort protocolLength = (ushort)(Protocol != null ? Encoding.UTF8.GetByteCount(Protocol) : 0);

            NetConvert.ToBuffer(labelLength, buffer, posn + 8);
            NetConvert.ToBuffer(protocolLength, buffer, posn + 10);

            posn += DCEP_OPEN_FIXED_PARAMETERS_LENGTH;

            if (labelLength > 0)
            {
                Buffer.BlockCopy(Encoding.UTF8.GetBytes(Label), 0, buffer, posn, labelLength);
                posn += labelLength;
            }

            if (protocolLength > 0)
            {
                Buffer.BlockCopy(Encoding.UTF8.GetBytes(Protocol), 0, buffer, posn, protocolLength);
                posn += protocolLength;
            }

            return (ushort)posn;
        }




        public byte[] GetBytes()
        {
            var buffer = new byte[GetLength()];
            WriteTo(buffer, 0);
            return buffer;
        }
    }
}
