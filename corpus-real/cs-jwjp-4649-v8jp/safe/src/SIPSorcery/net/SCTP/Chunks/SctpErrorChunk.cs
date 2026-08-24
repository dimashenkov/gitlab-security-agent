


















using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{






    public class SctpErrorChunk : SctpChunk
    {
        private const byte ABORT_CHUNK_TBIT_FLAG = 0x01;

        public List<ISctpErrorCause> ErrorCauses { get; private set; } = new List<ISctpErrorCause>();







        protected SctpErrorChunk(SctpChunkType chunkType, bool verificationTagBit)
            : base(chunkType)
        {
            if(verificationTagBit)
            {
                ChunkFlags = ABORT_CHUNK_TBIT_FLAG;
            }
        }

        public SctpErrorChunk() : base(SctpChunkType.ERROR)
        { }





        public SctpErrorChunk(SctpErrorCauseCode errorCauseCode) :
            this(new SctpCauseOnlyError(errorCauseCode))
        { }





        public SctpErrorChunk(ISctpErrorCause errorCause) : base(SctpChunkType.ERROR)
        {
            ErrorCauses.Add(errorCause);
        }





        public void AddErrorCause(ISctpErrorCause errorCause)
        {
            ErrorCauses.Add(errorCause);
        }






        public override ushort GetChunkLength(bool padded)
        {
            ushort len = SCTP_CHUNK_HEADER_LENGTH;
            if(ErrorCauses != null && ErrorCauses.Count > 0)
            {
                foreach(var cause in ErrorCauses)
                {
                    len += cause.GetErrorCauseLength(padded);
                }
            }
            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }








        public override ushort WriteTo(byte[] buffer, int posn)
        {
            WriteChunkHeader(buffer, posn);
            if (ErrorCauses != null && ErrorCauses.Count > 0)
            {
                int causePosn = posn + 4;
                foreach (var cause in ErrorCauses)
                {
                    causePosn += cause.WriteTo(buffer, causePosn);
                }
            }
            return GetChunkLength(true);
        }






        public static SctpErrorChunk ParseChunk(byte[] buffer, int posn, bool isAbort)
        {
            var errorChunk = (isAbort) ? new SctpAbortChunk(false) : new SctpErrorChunk();
            ushort chunkLen = errorChunk.ParseFirstWord(buffer, posn);

            int paramPosn = posn + SCTP_CHUNK_HEADER_LENGTH;
            int paramsBufferLength = chunkLen - SCTP_CHUNK_HEADER_LENGTH;

            if (paramPosn < paramsBufferLength)
            {
                bool stopProcessing = false;

                foreach (var varParam in GetParameters(buffer, paramPosn, paramsBufferLength))
                {
                    switch (varParam.ParameterType)
                    {
                        case (ushort)SctpErrorCauseCode.InvalidStreamIdentifier:
                            ushort streamID = (ushort)((varParam.ParameterValue != null) ?
                                NetConvert.ParseUInt16(varParam.ParameterValue, 0) : 0);
                            var invalidStreamID = new SctpErrorInvalidStreamIdentifier { StreamID = streamID };
                            errorChunk.AddErrorCause(invalidStreamID);
                            break;
                        case (ushort)SctpErrorCauseCode.MissingMandatoryParameter:
                            List<ushort> missingIDs = new List<ushort>();
                            if (varParam.ParameterValue != null)
                            {
                                for (int i = 0; i < varParam.ParameterValue.Length; i += 2)
                                {
                                    missingIDs.Add(NetConvert.ParseUInt16(varParam.ParameterValue, i));
                                }
                            }
                            var missingMandatory = new SctpErrorMissingMandatoryParameter { MissingParameters = missingIDs };
                            errorChunk.AddErrorCause(missingMandatory);
                            break;
                        case (ushort)SctpErrorCauseCode.StaleCookieError:
                            uint staleness = (uint)((varParam.ParameterValue != null) ?
                                NetConvert.ParseUInt32(varParam.ParameterValue, 0) : 0);
                            var staleCookie = new SctpErrorStaleCookieError { MeasureOfStaleness = staleness };
                            errorChunk.AddErrorCause(staleCookie);
                            break;
                        case (ushort)SctpErrorCauseCode.OutOfResource:
                            errorChunk.AddErrorCause(new SctpCauseOnlyError(SctpErrorCauseCode.OutOfResource));
                            break;
                        case (ushort)SctpErrorCauseCode.UnresolvableAddress:
                            var unresolvable = new SctpErrorUnresolvableAddress { UnresolvableAddress = varParam.ParameterValue };
                            errorChunk.AddErrorCause(unresolvable);
                            break;
                        case (ushort)SctpErrorCauseCode.UnrecognizedChunkType:
                            var unrecognised = new SctpErrorUnrecognizedChunkType { UnrecognizedChunk = varParam.ParameterValue };
                            errorChunk.AddErrorCause(unrecognised);
                            break;
                        case (ushort)SctpErrorCauseCode.InvalidMandatoryParameter:
                            errorChunk.AddErrorCause(new SctpCauseOnlyError(SctpErrorCauseCode.InvalidMandatoryParameter));
                            break;
                        case (ushort)SctpErrorCauseCode.UnrecognizedParameters:
                            var unrecognisedParams = new SctpErrorUnrecognizedParameters { UnrecognizedParameters = varParam.ParameterValue };
                            errorChunk.AddErrorCause(unrecognisedParams);
                            break;
                        case (ushort)SctpErrorCauseCode.NoUserData:
                            uint tsn = (uint)((varParam.ParameterValue != null) ?
                                NetConvert.ParseUInt32(varParam.ParameterValue, 0) : 0);
                            var noData = new SctpErrorNoUserData { TSN = tsn };
                            errorChunk.AddErrorCause(noData);
                            break;
                        case (ushort)SctpErrorCauseCode.CookieReceivedWhileShuttingDown:
                            errorChunk.AddErrorCause(new SctpCauseOnlyError(SctpErrorCauseCode.CookieReceivedWhileShuttingDown));
                            break;
                        case (ushort)SctpErrorCauseCode.RestartAssociationWithNewAddress:
                            var restartAddress = new SctpErrorRestartAssociationWithNewAddress
                            { NewAddressTLVs = varParam.ParameterValue };
                            errorChunk.AddErrorCause(restartAddress);
                            break;
                        case (ushort)SctpErrorCauseCode.UserInitiatedAbort:
                            string reason = (varParam.ParameterValue != null) ?
                                Encoding.UTF8.GetString(varParam.ParameterValue) : null;
                            var userAbort = new SctpErrorUserInitiatedAbort { AbortReason = reason };
                            errorChunk.AddErrorCause(userAbort);
                            break;
                        case (ushort)SctpErrorCauseCode.ProtocolViolation:
                            string info = (varParam.ParameterValue != null) ?
                                Encoding.UTF8.GetString(varParam.ParameterValue) : null;
                            var protocolViolation = new SctpErrorProtocolViolation { AdditionalInformation = info };
                            errorChunk.AddErrorCause(protocolViolation);
                            break;
                        default:

                            errorChunk.GotUnrecognisedParameter(varParam);
                            break;
                    }

                    if (stopProcessing)
                    {
                        logger.LogWarning("SCTP unrecognised parameter {ParameterType} for chunk type {ChunkType} indicated no further chunks should be processed.", varParam.ParameterType, SctpChunkType.ERROR);
                        break;
                    }
                }
            }

            return errorChunk;
        }
    }
}
