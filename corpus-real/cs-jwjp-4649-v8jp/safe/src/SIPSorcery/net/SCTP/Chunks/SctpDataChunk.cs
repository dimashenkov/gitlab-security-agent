


















using System;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public class SctpDataChunk : SctpChunk
    {





        public static SctpDataChunk EmptyDataChunk = new SctpDataChunk();




        public const int FIXED_PARAMETERS_LENGTH = 12;





        public bool Unordered { get; set; } = false;





        public bool Begining { get; set; } = true;





        public bool Ending { get; set; } = true;





        public uint TSN;




        public ushort StreamID;





        public ushort StreamSeqNum;






        public uint PPID;




        public byte[] UserData;


        internal DateTime LastSentAt;
        internal int SendCount;

        private SctpDataChunk()
            : base(SctpChunkType.DATA)
        { }















        public SctpDataChunk(
            bool isUnordered,
            bool isBegining,
            bool isEnd,
            uint tsn, 
            ushort streamID, 
            ushort seqnum, 
            uint ppid, 
            byte[] data) : base(SctpChunkType.DATA)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentNullException("data", "The SctpDataChunk data parameter cannot be empty.");
            }

            Unordered = isUnordered;
            Begining = isBegining;
            Ending = isEnd;
            TSN = tsn;
            StreamID = streamID;
            StreamSeqNum = seqnum; 
            PPID = ppid;
            UserData = data;

            ChunkFlags = (byte)(
                (Unordered ? 0x04 : 0x0) +
                (Begining ? 0x02 : 0x0) +
                (Ending ? 0x01 : 0x0));
        }






        public override ushort GetChunkLength(bool padded)
        {
            ushort len = SCTP_CHUNK_HEADER_LENGTH + FIXED_PARAMETERS_LENGTH;
            len += (ushort)(UserData != null ? UserData.Length : 0);
            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }








        public override ushort WriteTo(byte[] buffer, int posn)
        {
            WriteChunkHeader(buffer, posn);


            int startPosn = posn + SCTP_CHUNK_HEADER_LENGTH;

            NetConvert.ToBuffer(TSN, buffer, startPosn);
            NetConvert.ToBuffer(StreamID, buffer, startPosn + 4);
            NetConvert.ToBuffer(StreamSeqNum, buffer, startPosn + 6);
            NetConvert.ToBuffer(PPID, buffer, startPosn + 8);

            int userDataPosn = startPosn + FIXED_PARAMETERS_LENGTH;

            if (UserData != null)
            {
                Buffer.BlockCopy(UserData, 0, buffer, userDataPosn, UserData.Length);
            }

            return GetChunkLength(true);
        }

        public bool IsEmpty()
        {
            return UserData == null;
        }






        public static SctpDataChunk ParseChunk(byte[] buffer, int posn)
        {
            var dataChunk = new SctpDataChunk();
            ushort chunkLen = dataChunk.ParseFirstWord(buffer, posn);

            if (chunkLen < FIXED_PARAMETERS_LENGTH)
            {
                throw new ApplicationException($"SCTP data chunk cannot be parsed as buffer too short for fixed parameter fields.");
            }

            dataChunk.Unordered = (dataChunk.ChunkFlags & 0x04) > 0;
            dataChunk.Begining = (dataChunk.ChunkFlags & 0x02) > 0;
            dataChunk.Ending = (dataChunk.ChunkFlags & 0x01) > 0;

            int startPosn = posn + SCTP_CHUNK_HEADER_LENGTH;

            dataChunk.TSN = NetConvert.ParseUInt32(buffer, startPosn);
            dataChunk.StreamID = NetConvert.ParseUInt16(buffer, startPosn + 4);
            dataChunk.StreamSeqNum = NetConvert.ParseUInt16(buffer, startPosn + 6);
            dataChunk.PPID = NetConvert.ParseUInt32(buffer, startPosn + 8);

            int userDataPosn = startPosn + FIXED_PARAMETERS_LENGTH;
            int userDataLen = chunkLen - SCTP_CHUNK_HEADER_LENGTH - FIXED_PARAMETERS_LENGTH;

            if (userDataLen > 0)
            {
                dataChunk.UserData = new byte[userDataLen];
                Buffer.BlockCopy(buffer, userDataPosn, dataChunk.UserData, 0, dataChunk.UserData.Length);
            }

            return dataChunk;
        }
    }
}
