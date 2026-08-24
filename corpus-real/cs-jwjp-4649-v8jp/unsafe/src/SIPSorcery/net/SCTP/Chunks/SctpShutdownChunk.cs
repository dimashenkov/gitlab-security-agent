


















using SIPSorcery.Sys;

namespace SIPSorcery.Net
{







    public class SctpShutdownChunk : SctpChunk
    {
        public const int FIXED_PARAMETERS_LENGTH = 4;





        public uint? CumulativeTsnAck;

        private SctpShutdownChunk() : base(SctpChunkType.SHUTDOWN)
        { }





        public SctpShutdownChunk(uint? cumulativeTsnAck) : base(SctpChunkType.SHUTDOWN)
        {
            CumulativeTsnAck = cumulativeTsnAck;
        }






        public override ushort GetChunkLength(bool padded)
        {
            return SCTP_CHUNK_HEADER_LENGTH + FIXED_PARAMETERS_LENGTH;
        }








        public override ushort WriteTo(byte[] buffer, int posn)
        {
            WriteChunkHeader(buffer, posn);
            NetConvert.ToBuffer(CumulativeTsnAck.GetValueOrDefault(), buffer, posn + SCTP_CHUNK_HEADER_LENGTH);
            return GetChunkLength(true);
        }






        public static SctpShutdownChunk ParseChunk(byte[] buffer, int posn)
        {
            var shutdownChunk = new SctpShutdownChunk();
            shutdownChunk.CumulativeTsnAck = NetConvert.ParseUInt32(buffer, posn + SCTP_CHUNK_HEADER_LENGTH);
            return shutdownChunk;
        }
    }
}
