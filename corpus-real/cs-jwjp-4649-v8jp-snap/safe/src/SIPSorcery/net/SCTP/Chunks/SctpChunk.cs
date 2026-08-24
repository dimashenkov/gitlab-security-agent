


















using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public static class SctpPadding
    {
        public static ushort PadTo4ByteBoundary(int val)
        {
            return (ushort)(val % 4 == 0 ? val : val + 4 - val % 4);
        }
    }







    public enum SctpChunkType : byte
    {
        DATA = 0,
        INIT = 1,
        INIT_ACK = 2,
        SACK = 3,
        HEARTBEAT = 4,
        HEARTBEAT_ACK = 5,
        ABORT = 6,
        SHUTDOWN = 7,
        SHUTDOWN_ACK = 8,
        ERROR = 9,
        COOKIE_ECHO = 10,
        COOKIE_ACK = 11,
        ECNE = 12,
        CWR = 13,
        SHUTDOWN_COMPLETE = 14,








    }








    public enum SctpUnrecognisedChunkActions : byte
    {



        Stop = 0x00,





        StopAndReport = 0x01,




        Skip = 0x02,





        SkipAndReport = 0x03
    }

    public class SctpChunk
    {
        public const int SCTP_CHUNK_HEADER_LENGTH = 4;

        protected static ILogger logger = SIPSorcery.LogFactory.CreateLogger<SctpChunk>();





        public byte ChunkType;






        public byte ChunkFlags;






        public byte[] ChunkValue;




        public SctpChunkType? KnownType
        {
            get
            {
                if (Enum.IsDefined(typeof(SctpChunkType), ChunkType))
                {
                    return (SctpChunkType)ChunkType;
                }
                else
                {
                    return null;
                }
            }
        }





        public List<SctpTlvChunkParameter> UnrecognizedPeerParameters = new List<SctpTlvChunkParameter>();

        public SctpChunk(SctpChunkType chunkType, byte chunkFlags = 0x00)
        {
            ChunkType = (byte)chunkType;
            ChunkFlags = chunkFlags;
        }






        protected SctpChunk()
        { }








        public virtual ushort GetChunkLength(bool padded)
        {
            var len = (ushort)(SCTP_CHUNK_HEADER_LENGTH
                + (ChunkValue == null ? 0 : ChunkValue.Length));

            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }








        public ushort ParseFirstWord(byte[] buffer, int posn)
        {
            ChunkType = buffer[posn];
            ChunkFlags = buffer[posn + 1];
            ushort chunkLength = NetConvert.ParseUInt16(buffer, posn + 2);

            if (chunkLength > 0 && buffer.Length < posn + chunkLength)
            {

                int bytesRequired = chunkLength;
                int bytesAvailable = buffer.Length - posn;
                throw new ApplicationException($"The SCTP chunk buffer was too short. Required {bytesRequired} bytes but only {bytesAvailable} available.");
            }

            return chunkLength;
        }








        protected void WriteChunkHeader(byte[] buffer, int posn)
        {
            buffer[posn] = ChunkType;
            buffer[posn + 1] = ChunkFlags;
            NetConvert.ToBuffer(GetChunkLength(false), buffer, posn + 2);
        }










        public virtual ushort WriteTo(byte[] buffer, int posn)
        {
            WriteChunkHeader(buffer, posn);

            if (ChunkValue?.Length > 0)
            {
                Buffer.BlockCopy(ChunkValue, 0, buffer, posn + SCTP_CHUNK_HEADER_LENGTH, ChunkValue.Length);
            }

            return GetChunkLength(true);
        }








        public bool GotUnrecognisedParameter(SctpTlvChunkParameter chunkParameter)
        {
            bool stop = false;

            switch (chunkParameter.UnrecognisedAction)
            {
                case SctpUnrecognisedParameterActions.Stop:
                    stop = true;
                    break;
                case SctpUnrecognisedParameterActions.StopAndReport:
                    stop = true;
                    UnrecognizedPeerParameters.Add(chunkParameter);
                    break;
                case SctpUnrecognisedParameterActions.Skip:
                    break;
                case SctpUnrecognisedParameterActions.SkipAndReport:
                    UnrecognizedPeerParameters.Add(chunkParameter);
                    break;
            }

            return stop;
        }










        public static SctpChunk ParseBaseChunk(byte[] buffer, int posn)
        {
            var chunk = new SctpChunk();
            ushort chunkLength = chunk.ParseFirstWord(buffer, posn);
            if (chunkLength > SCTP_CHUNK_HEADER_LENGTH)
            {
                chunk.ChunkValue = new byte[chunkLength - SCTP_CHUNK_HEADER_LENGTH];
                Buffer.BlockCopy(buffer, posn + SCTP_CHUNK_HEADER_LENGTH, chunk.ChunkValue, 0, chunk.ChunkValue.Length);
            }

            return chunk;
        }










        public static IEnumerable<SctpTlvChunkParameter> GetParameters(byte[] buffer, int posn, int length)
        {
            int paramPosn = posn;

            while (paramPosn < posn + length)
            {
                var chunkParam = SctpTlvChunkParameter.ParseTlvParameter(buffer, paramPosn);

                yield return chunkParam;

                paramPosn += chunkParam.GetParameterLength(true);
            }
        }







        public static SctpChunk Parse(byte[] buffer, int posn)
        {
            if (buffer.Length < posn + SCTP_CHUNK_HEADER_LENGTH)
            {
                throw new ApplicationException("Buffer did not contain the minimum of bytes for an SCTP chunk.");
            }

            byte chunkType = buffer[posn];

            if (Enum.IsDefined(typeof(SctpChunkType), chunkType))
            {
                switch ((SctpChunkType)chunkType)
                {
                    case SctpChunkType.ABORT:
                        return SctpAbortChunk.ParseChunk(buffer, posn, true);
                    case SctpChunkType.DATA:
                        return SctpDataChunk.ParseChunk(buffer, posn);
                    case SctpChunkType.ERROR:
                        return SctpErrorChunk.ParseChunk(buffer, posn, false);
                    case SctpChunkType.SACK:
                        return SctpSackChunk.ParseChunk(buffer, posn);
                    case SctpChunkType.COOKIE_ACK:
                    case SctpChunkType.COOKIE_ECHO:
                    case SctpChunkType.HEARTBEAT:
                    case SctpChunkType.HEARTBEAT_ACK:
                    case SctpChunkType.SHUTDOWN_ACK:
                    case SctpChunkType.SHUTDOWN_COMPLETE:
                        return ParseBaseChunk(buffer, posn);
                    case SctpChunkType.INIT:
                    case SctpChunkType.INIT_ACK:
                        return SctpInitChunk.ParseChunk(buffer, posn);
                    case SctpChunkType.SHUTDOWN:
                        return SctpShutdownChunk.ParseChunk(buffer, posn);
                    default:
                        logger.LogDebug("TODO: Implement parsing logic for well known chunk type {ChunkType}.", (SctpChunkType)chunkType);
                        return ParseBaseChunk(buffer, posn);
                }
            }



            throw new ApplicationException($"SCTP chunk type of {chunkType} was not recognised.");
        }








        public static uint GetChunkLengthFromHeader(byte[] buffer, int posn, bool padded)
        {
            ushort len = NetConvert.ParseUInt16(buffer, posn + 2);
            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }





        public static SctpUnrecognisedChunkActions GetUnrecognisedChunkAction(ushort chunkType) =>
            (SctpUnrecognisedChunkActions)(chunkType >> 14 & 0x03);








        public static byte[] CopyUnrecognisedChunk(byte[] buffer, int posn)
        {
            byte[] unrecognised = new byte[SctpChunk.GetChunkLengthFromHeader(buffer, posn, true)];
            Buffer.BlockCopy(buffer, posn, unrecognised, 0, unrecognised.Length);
            return unrecognised;
        }
    }
}
