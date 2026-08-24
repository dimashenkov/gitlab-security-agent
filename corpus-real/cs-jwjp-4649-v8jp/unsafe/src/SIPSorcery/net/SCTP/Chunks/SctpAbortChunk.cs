


















using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;

namespace SIPSorcery.Net
{












    public class SctpAbortChunk : SctpErrorChunk
    {





        public SctpAbortChunk(bool verificationTagBit) :
            base(SctpChunkType.ABORT, verificationTagBit)
        { }





        public string GetAbortReason()
        {
            if (ErrorCauses.Any(x => x.CauseCode == SctpErrorCauseCode.UserInitiatedAbort))
            {
                var userAbort = (SctpErrorUserInitiatedAbort)(ErrorCauses
                    .First(x => x.CauseCode == SctpErrorCauseCode.UserInitiatedAbort));
                return userAbort.AbortReason;
            }
            else if(ErrorCauses.Any(x => x.CauseCode == SctpErrorCauseCode.ProtocolViolation))
            {
                var protoViolation = (SctpErrorProtocolViolation)(ErrorCauses
                    .First(x => x.CauseCode == SctpErrorCauseCode.ProtocolViolation));
                return protoViolation.AdditionalInformation;
            }
            else
            {
                return null;
            }
        }
    }
}
