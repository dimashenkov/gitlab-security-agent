



















using System;
using System.Collections.Generic;
using System.Text;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{



    public enum SctpErrorCauseCode : ushort
    {
        InvalidStreamIdentifier = 1,
        MissingMandatoryParameter = 2,
        StaleCookieError = 3,
        OutOfResource = 4,
        UnresolvableAddress = 5,
        UnrecognizedChunkType = 6,
        InvalidMandatoryParameter = 7,
        UnrecognizedParameters = 8,
        NoUserData = 9,
        CookieReceivedWhileShuttingDown = 10,
        RestartAssociationWithNewAddress = 11,
        UserInitiatedAbort = 12,
        ProtocolViolation = 13
    }

    public interface ISctpErrorCause
    {
        SctpErrorCauseCode CauseCode { get; }
        ushort GetErrorCauseLength(bool padded);
        int WriteTo(byte[] buffer, int posn);
    }










    public struct SctpCauseOnlyError : ISctpErrorCause
    {
        private const ushort ERROR_CAUSE_LENGTH = 4;

        public static readonly List<SctpErrorCauseCode> SupportedErrorCauses =
            new List<SctpErrorCauseCode>
            {
                SctpErrorCauseCode.OutOfResource,
                SctpErrorCauseCode.InvalidMandatoryParameter,
                SctpErrorCauseCode.CookieReceivedWhileShuttingDown
            };

        public SctpErrorCauseCode CauseCode { get; private set; }

        public SctpCauseOnlyError(SctpErrorCauseCode causeCode)
        {
            if (!SupportedErrorCauses.Contains(causeCode))
            {
                throw new ApplicationException($"SCTP error struct should not be used for {causeCode}, use the specific error type.");
            }

            CauseCode = causeCode;
        }

        public ushort GetErrorCauseLength(bool padded) => ERROR_CAUSE_LENGTH;

        public int WriteTo(byte[] buffer, int posn)
        {
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(ERROR_CAUSE_LENGTH, buffer, posn + 2);
            return ERROR_CAUSE_LENGTH;
        }
    }








    public struct SctpErrorInvalidStreamIdentifier : ISctpErrorCause
    {
        private const ushort ERROR_CAUSE_LENGTH = 8;

        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.InvalidStreamIdentifier;




        public ushort StreamID;

        public ushort GetErrorCauseLength(bool padded) => ERROR_CAUSE_LENGTH;

        public int WriteTo(byte[] buffer, int posn)
        {
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(ERROR_CAUSE_LENGTH, buffer, posn + 2);
            NetConvert.ToBuffer(StreamID, buffer, posn + 4);
            return ERROR_CAUSE_LENGTH;
        }
    }








    public struct SctpErrorMissingMandatoryParameter : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.MissingMandatoryParameter;

        public List<ushort> MissingParameters;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((MissingParameters != null) ? MissingParameters.Count * 2 : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (MissingParameters != null)
            {
                int valPosn = posn + 4;
                foreach (var missing in MissingParameters)
                {
                    NetConvert.ToBuffer(missing, buffer, valPosn);
                    valPosn += 2;
                }
            }
            return len;
        }
    }







    public struct SctpErrorStaleCookieError : ISctpErrorCause
    {
        private const ushort ERROR_CAUSE_LENGTH = 8;

        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.StaleCookieError;




        public uint MeasureOfStaleness;

        public ushort GetErrorCauseLength(bool padded) => ERROR_CAUSE_LENGTH;

        public int WriteTo(byte[] buffer, int posn)
        {
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(ERROR_CAUSE_LENGTH, buffer, posn + 2);
            NetConvert.ToBuffer(MeasureOfStaleness, buffer, posn + 4);
            return ERROR_CAUSE_LENGTH;
        }
    }









    public struct SctpErrorUnresolvableAddress : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.UnresolvableAddress;






        public byte[] UnresolvableAddress;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((UnresolvableAddress != null) ? UnresolvableAddress.Length : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (UnresolvableAddress != null)
            {
                Buffer.BlockCopy(UnresolvableAddress, 0, buffer, posn + 4, UnresolvableAddress.Length);
            }
            return len;
        }
    }








    public struct SctpErrorUnrecognizedChunkType : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.UnrecognizedChunkType;






        public byte[] UnrecognizedChunk;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((UnrecognizedChunk != null) ? UnrecognizedChunk.Length : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (UnrecognizedChunk != null)
            {
                Buffer.BlockCopy(UnrecognizedChunk, 0, buffer, posn + 4, UnrecognizedChunk.Length);
            }
            return len;
        }
    }









    public struct SctpErrorUnrecognizedParameters : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.UnrecognizedParameters;









        public byte[] UnrecognizedParameters;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((UnrecognizedParameters != null) ? UnrecognizedParameters.Length : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (UnrecognizedParameters != null)
            {
                Buffer.BlockCopy(UnrecognizedParameters, 0, buffer, posn + 4, UnrecognizedParameters.Length);
            }
            return len;
        }
    }








    public struct SctpErrorNoUserData : ISctpErrorCause
    {
        private const ushort ERROR_CAUSE_LENGTH = 8;

        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.NoUserData;





        public uint TSN;

        public ushort GetErrorCauseLength(bool padded) => ERROR_CAUSE_LENGTH;

        public int WriteTo(byte[] buffer, int posn)
        {
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(ERROR_CAUSE_LENGTH, buffer, posn + 2);
            NetConvert.ToBuffer(TSN, buffer, posn + 4);
            return ERROR_CAUSE_LENGTH;
        }
    }









    public struct SctpErrorRestartAssociationWithNewAddress : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.RestartAssociationWithNewAddress;






        public byte[] NewAddressTLVs;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((NewAddressTLVs != null) ? NewAddressTLVs.Length : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (NewAddressTLVs != null)
            {
                Buffer.BlockCopy(NewAddressTLVs, 0, buffer, posn + 4, NewAddressTLVs.Length);
            }
            return len;
        }
    }








    public struct SctpErrorUserInitiatedAbort : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.UserInitiatedAbort;




        public string AbortReason;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((!string.IsNullOrEmpty(AbortReason)) ? Encoding.UTF8.GetByteCount(AbortReason) : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (!string.IsNullOrEmpty(AbortReason))
            {
                var reasonBuffer = Encoding.UTF8.GetBytes(AbortReason);
                Buffer.BlockCopy(reasonBuffer, 0, buffer, posn + 4, reasonBuffer.Length);
            }
            return len;
        }
    }









    public struct SctpErrorProtocolViolation : ISctpErrorCause
    {
        public SctpErrorCauseCode CauseCode => SctpErrorCauseCode.ProtocolViolation;




        public string AdditionalInformation;

        public ushort GetErrorCauseLength(bool padded)
        {
            ushort len = (ushort)(4 + ((!string.IsNullOrEmpty(AdditionalInformation)) ? Encoding.UTF8.GetByteCount(AdditionalInformation) : 0));
            return padded ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }

        public int WriteTo(byte[] buffer, int posn)
        {
            var len = GetErrorCauseLength(true);
            NetConvert.ToBuffer((ushort)CauseCode, buffer, posn);
            NetConvert.ToBuffer(len, buffer, posn + 2);
            if (!string.IsNullOrEmpty(AdditionalInformation))
            {
                var reasonBuffer = Encoding.UTF8.GetBytes(AdditionalInformation);
                Buffer.BlockCopy(reasonBuffer, 0, buffer, posn + 4, reasonBuffer.Length);
            }
            return len;
        }
    }
}
