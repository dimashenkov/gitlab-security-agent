



















using System;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{







































    public enum SctpUnrecognisedParameterActions : byte
    {



        Stop = 0x00,





        StopAndReport = 0x01,




        Skip = 0x02,




        SkipAndReport = 0x03
    }














    public class SctpTlvChunkParameter
    {
        public const int SCTP_PARAMETER_HEADER_LENGTH = 4;

        private static ILogger logger = SIPSorcery.LogFactory.CreateLogger<SctpTlvChunkParameter>();




        public ushort ParameterType { get; protected set; }




        public byte[] ParameterValue;





        public SctpUnrecognisedParameterActions UnrecognisedAction =>
            (SctpUnrecognisedParameterActions) (ParameterType >> 14 & 0x03);

        protected SctpTlvChunkParameter()
        { }




        public SctpTlvChunkParameter(ushort parameterType, byte[] parameterValue)
        {
            ParameterType = parameterType;
            ParameterValue = parameterValue;
        }







        public virtual ushort GetParameterLength(bool padded)
        {
            ushort len = (ushort)(SCTP_PARAMETER_HEADER_LENGTH
                + (ParameterValue == null ? 0 : ParameterValue.Length));

            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }







        protected void WriteParameterHeader(byte[] buffer, int posn)
        {
            NetConvert.ToBuffer(ParameterType, buffer, posn);
            NetConvert.ToBuffer(GetParameterLength(false), buffer, posn + 2);
        }










        public virtual int WriteTo(byte[] buffer, int posn)
        {
            WriteParameterHeader(buffer, posn);

            if (ParameterValue?.Length > 0)
            {
                Buffer.BlockCopy(ParameterValue, 0, buffer, posn + SCTP_PARAMETER_HEADER_LENGTH, ParameterValue.Length);
            }

            return GetParameterLength(true);
        }





        public byte[] GetBytes()
        {
            byte[] buffer = new byte[GetParameterLength(true)];
            WriteTo(buffer, 0);
            return buffer;
        }







        public ushort ParseFirstWord(byte[] buffer, int posn)
        {
            ParameterType = NetConvert.ParseUInt16(buffer, posn);
            ushort paramLen = NetConvert.ParseUInt16(buffer, posn + 2);

            if (paramLen > 0 && buffer.Length < posn + paramLen)
            {

                int bytesRequired = paramLen;
                int bytesAvailable = buffer.Length - posn;
                throw new ApplicationException($"The SCTP chunk parameter buffer was too short. Required {bytesRequired} bytes but only {bytesAvailable} available.");
            }

            return paramLen;
        }







        public static SctpTlvChunkParameter ParseTlvParameter(byte[] buffer, int posn)
        {
            if (buffer.Length < posn + SCTP_PARAMETER_HEADER_LENGTH)
            {
                throw new ApplicationException("Buffer did not contain the minimum of bytes for an SCTP TLV chunk parameter.");
            }

            var tlvParam = new SctpTlvChunkParameter();
            ushort paramLen = tlvParam.ParseFirstWord(buffer, posn);
            if (paramLen > SCTP_PARAMETER_HEADER_LENGTH)
            {
                tlvParam.ParameterValue = new byte[paramLen - SCTP_PARAMETER_HEADER_LENGTH];
                Buffer.BlockCopy(buffer, posn + SCTP_PARAMETER_HEADER_LENGTH, tlvParam.ParameterValue,
                    0, tlvParam.ParameterValue.Length);
            }
            return tlvParam;
        }
    }
}
