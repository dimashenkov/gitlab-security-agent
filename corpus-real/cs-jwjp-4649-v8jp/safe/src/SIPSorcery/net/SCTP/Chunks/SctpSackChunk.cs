


















using System.Collections.Generic;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{






    public class SctpSackChunk : SctpChunk
    {
        public const int FIXED_PARAMETERS_LENGTH = 12;
        private const int GAP_REPORT_LENGTH = 4;
        private const int DUPLICATE_TSN_LENGTH = 4;





        public uint CumulativeTsnAck;





        public uint ARwnd;





        public List<SctpTsnGapBlock> GapAckBlocks = new List<SctpTsnGapBlock>();





        public List<uint> DuplicateTSN = new List<uint>();

        private SctpSackChunk() : base(SctpChunkType.SACK)
        { }






        public SctpSackChunk(uint cumulativeTsnAck, uint arwnd) : base(SctpChunkType.SACK)
        {
            CumulativeTsnAck = cumulativeTsnAck;
            ARwnd = arwnd;
        }






        public override ushort GetChunkLength(bool padded)
        {
            var len = (ushort)(SCTP_CHUNK_HEADER_LENGTH + 
                FIXED_PARAMETERS_LENGTH +
                GapAckBlocks.Count * GAP_REPORT_LENGTH +
                DuplicateTSN.Count * DUPLICATE_TSN_LENGTH);


            return len;
        }








        public override ushort WriteTo(byte[] buffer, int posn)
        {
            WriteChunkHeader(buffer, posn);

            ushort startPosn = (ushort)(posn + SCTP_CHUNK_HEADER_LENGTH);

            NetConvert.ToBuffer(CumulativeTsnAck, buffer, startPosn);
            NetConvert.ToBuffer(ARwnd, buffer, startPosn + 4);
            NetConvert.ToBuffer((ushort)GapAckBlocks.Count, buffer, startPosn + 8);
            NetConvert.ToBuffer((ushort)DuplicateTSN.Count, buffer, startPosn + 10);

            int reportPosn = startPosn + FIXED_PARAMETERS_LENGTH;

            foreach (var gapBlock in GapAckBlocks)
            {
                NetConvert.ToBuffer(gapBlock.Start, buffer, reportPosn);
                NetConvert.ToBuffer(gapBlock.End, buffer, reportPosn + 2);
                reportPosn += GAP_REPORT_LENGTH;
            }

            foreach(var dupTSN in DuplicateTSN)
            {
                NetConvert.ToBuffer(dupTSN, buffer, reportPosn);
                reportPosn += DUPLICATE_TSN_LENGTH;
            }

            return GetChunkLength(true);
        }






        public static SctpSackChunk ParseChunk(byte[] buffer, int posn)
        {
            var sackChunk = new SctpSackChunk();
            ushort chunkLen = sackChunk.ParseFirstWord(buffer, posn);

            ushort startPosn = (ushort)(posn + SCTP_CHUNK_HEADER_LENGTH);

            sackChunk.CumulativeTsnAck = NetConvert.ParseUInt32(buffer, startPosn);
            sackChunk.ARwnd = NetConvert.ParseUInt32(buffer, startPosn + 4);
            ushort numGapAckBlocks = NetConvert.ParseUInt16(buffer, startPosn + 8);
            ushort numDuplicateTSNs = NetConvert.ParseUInt16(buffer, startPosn + 10);

            int reportPosn = startPosn + FIXED_PARAMETERS_LENGTH;

            for (int i=0; i < numGapAckBlocks; i++)
            {
                ushort start = NetConvert.ParseUInt16(buffer, reportPosn);
                ushort end = NetConvert.ParseUInt16(buffer, reportPosn + 2);
                sackChunk.GapAckBlocks.Add(new SctpTsnGapBlock { Start = start, End = end });
                reportPosn += GAP_REPORT_LENGTH;
            }

            for(int j=0; j < numDuplicateTSNs; j++)
            {
                sackChunk.DuplicateTSN.Add(NetConvert.ParseUInt32(buffer, reportPosn));
                reportPosn += DUPLICATE_TSN_LENGTH;
            }

            return sackChunk;
        }
    }
}
