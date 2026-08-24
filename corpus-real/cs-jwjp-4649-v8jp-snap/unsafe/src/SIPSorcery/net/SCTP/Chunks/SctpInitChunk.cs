


















using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{




    public enum SctpInitChunkParameterType : ushort
    {
        IPv4Address = 5,
        IPv6Address = 6,
        StateCookie = 7,
        UnrecognizedParameter = 8,
        CookiePreservative = 9,
        HostNameAddress = 11,
        SupportedAddressTypes = 12,
        EcnCapable = 32768
    }









    public class SctpInitChunk : SctpChunk
    {
        public const int FIXED_PARAMETERS_LENGTH = 16;


        private const ushort PARAMVAL_LENGTH_IPV4 = 4;
        private const ushort PARAMVAL_LENGTH_IPV6 = 16;
        private const ushort PARAMVAL_LENGTH_COOKIE_PRESERVATIVE = 4;







        public uint InitiateTag;






        public uint ARwnd;





        public ushort NumberOutboundStreams;





        public ushort NumberInboundStreams;




        public uint InitialTSN;




        public List<IPAddress> Addresses = new List<IPAddress>();





        public uint CookiePreservative;







        public string HostnameAddress;





        public List<SctpInitChunkParameterType> SupportedAddressTypes = new List<SctpInitChunkParameterType>();






        public byte[] StateCookie;







        public List<byte[]> UnrecognizedParameters = new List<byte[]>();

        private SctpInitChunk()
        { }





        public SctpInitChunk(SctpChunkType initChunkType,
            uint initiateTag,
            uint initialTSN,
            uint arwnd,
            ushort numberOutboundStreams,
            ushort numberInboundStreams) : base(initChunkType)
        {
            InitiateTag = initiateTag;
            NumberOutboundStreams = numberOutboundStreams;
            NumberInboundStreams = numberInboundStreams;
            InitialTSN = initialTSN;
            ARwnd = arwnd;
        }







        private ushort GetVariableParametersLength(bool padded)
        {
            int len = 0;

            len += Addresses.Count(x => x.AddressFamily == AddressFamily.InterNetwork) *
                (SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH + PARAMVAL_LENGTH_IPV4);

            len += Addresses.Count(x => x.AddressFamily == AddressFamily.InterNetworkV6) *
                (SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH + PARAMVAL_LENGTH_IPV6);

            if (CookiePreservative > 0)
            {
                len += SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH +
                    PARAMVAL_LENGTH_COOKIE_PRESERVATIVE;
            }

            if (!string.IsNullOrEmpty(HostnameAddress))
            {
                len += SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH +
                    SctpPadding.PadTo4ByteBoundary(Encoding.UTF8.GetByteCount(HostnameAddress));
            }

            if (SupportedAddressTypes.Count > 0)
            {
                len += SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH +
                    SctpPadding.PadTo4ByteBoundary(SupportedAddressTypes.Count * 2);
            }

            if (StateCookie != null)
            {
                len += SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH +
                    SctpPadding.PadTo4ByteBoundary(StateCookie.Length);
            }

            foreach (var unrecognised in UnrecognizedPeerParameters)
            {
                len += SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH +
                    unrecognised.GetParameterLength(true);
            }

            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : (ushort)len;
        }






        private List<SctpTlvChunkParameter> GetVariableParameters()
        {
            List<SctpTlvChunkParameter> varParams = new List<SctpTlvChunkParameter>();


            foreach (var address in Addresses)
            {
                ushort addrParamType = (ushort)(address.AddressFamily == AddressFamily.InterNetwork ?
                    SctpInitChunkParameterType.IPv4Address : SctpInitChunkParameterType.IPv6Address);
                var addrParam = new SctpTlvChunkParameter(addrParamType, address.GetAddressBytes());
                varParams.Add(addrParam);
            }

            if (CookiePreservative > 0)
            {
                varParams.Add(
                    new SctpTlvChunkParameter((ushort)SctpInitChunkParameterType.CookiePreservative,
                    NetConvert.GetBytes(CookiePreservative)
                    ));
            }

            if (!string.IsNullOrEmpty(HostnameAddress))
            {
                varParams.Add(
                    new SctpTlvChunkParameter((ushort)SctpInitChunkParameterType.HostNameAddress,
                    Encoding.UTF8.GetBytes(HostnameAddress)
                    ));
            }

            if (SupportedAddressTypes.Count > 0)
            {
                byte[] paramVal = new byte[SupportedAddressTypes.Count * 2];
                int paramValPosn = 0;
                foreach (var supAddr in SupportedAddressTypes)
                {
                    NetConvert.ToBuffer((ushort)supAddr, paramVal, paramValPosn);
                    paramValPosn += 2;
                }
                varParams.Add(
                    new SctpTlvChunkParameter((ushort)SctpInitChunkParameterType.SupportedAddressTypes, paramVal));
            }

            if (StateCookie != null)
            {
                varParams.Add(
                    new SctpTlvChunkParameter((ushort)SctpInitChunkParameterType.StateCookie, StateCookie));
            }

            foreach (var unrecognised in UnrecognizedPeerParameters)
            {
                varParams.Add(
                   new SctpTlvChunkParameter((ushort)SctpInitChunkParameterType.UnrecognizedParameter, unrecognised.GetBytes()));
            }

            return varParams;
        }






        public override ushort GetChunkLength(bool padded)
        {
            var len = (ushort)(SCTP_CHUNK_HEADER_LENGTH +
                FIXED_PARAMETERS_LENGTH +
                GetVariableParametersLength(false));

            return (padded) ? SctpPadding.PadTo4ByteBoundary(len) : len;
        }








        public override ushort WriteTo(byte[] buffer, int posn)
        {
            WriteChunkHeader(buffer, posn);


            int startPosn = posn + SCTP_CHUNK_HEADER_LENGTH;

            NetConvert.ToBuffer(InitiateTag, buffer, startPosn);
            NetConvert.ToBuffer(ARwnd, buffer, startPosn + 4);
            NetConvert.ToBuffer(NumberOutboundStreams, buffer, startPosn + 8);
            NetConvert.ToBuffer(NumberInboundStreams, buffer, startPosn + 10);
            NetConvert.ToBuffer(InitialTSN, buffer, startPosn + 12);

            var varParameters = GetVariableParameters();


            if (varParameters.Count > 0)
            {
                int paramPosn = startPosn + FIXED_PARAMETERS_LENGTH;
                foreach (var optParam in varParameters)
                {
                    paramPosn += optParam.WriteTo(buffer, paramPosn);
                }
            }

            return GetChunkLength(true);
        }






        public static SctpInitChunk ParseChunk(byte[] buffer, int posn)
        {
            var initChunk = new SctpInitChunk();
            ushort chunkLen = initChunk.ParseFirstWord(buffer, posn);

            int startPosn = posn + SCTP_CHUNK_HEADER_LENGTH;

            initChunk.InitiateTag = NetConvert.ParseUInt32(buffer, startPosn);
            initChunk.ARwnd = NetConvert.ParseUInt32(buffer, startPosn + 4);
            initChunk.NumberOutboundStreams = NetConvert.ParseUInt16(buffer, startPosn + 8);
            initChunk.NumberInboundStreams = NetConvert.ParseUInt16(buffer, startPosn + 10);
            initChunk.InitialTSN = NetConvert.ParseUInt32(buffer, startPosn + 12);

            int paramPosn = startPosn + FIXED_PARAMETERS_LENGTH;
            int paramsBufferLength = chunkLen - SCTP_CHUNK_HEADER_LENGTH - FIXED_PARAMETERS_LENGTH;

            if (paramPosn < paramsBufferLength)
            {
                bool stopProcessing = false;

                foreach (var varParam in GetParameters(buffer, paramPosn, paramsBufferLength))
                {
                    switch (varParam.ParameterType)
                    {
                        case (ushort)SctpInitChunkParameterType.IPv4Address:
                        case (ushort)SctpInitChunkParameterType.IPv6Address:
                            var address = new IPAddress(varParam.ParameterValue);
                            initChunk.Addresses.Add(address);
                            break;

                        case (ushort)SctpInitChunkParameterType.CookiePreservative:
                            initChunk.CookiePreservative = NetConvert.ParseUInt32(varParam.ParameterValue, 0);
                            break;

                        case (ushort)SctpInitChunkParameterType.HostNameAddress:
                            initChunk.HostnameAddress = Encoding.UTF8.GetString(varParam.ParameterValue);
                            break;

                        case (ushort)SctpInitChunkParameterType.SupportedAddressTypes:
                            for (int valPosn = 0; valPosn < varParam.ParameterValue.Length; valPosn += 2)
                            {
                                switch (NetConvert.ParseUInt16(varParam.ParameterValue, valPosn))
                                {
                                    case (ushort)SctpInitChunkParameterType.IPv4Address:
                                        initChunk.SupportedAddressTypes.Add(SctpInitChunkParameterType.IPv4Address);
                                        break;
                                    case (ushort)SctpInitChunkParameterType.IPv6Address:
                                        initChunk.SupportedAddressTypes.Add(SctpInitChunkParameterType.IPv6Address);
                                        break;
                                    case (ushort)SctpInitChunkParameterType.HostNameAddress:
                                        initChunk.SupportedAddressTypes.Add(SctpInitChunkParameterType.HostNameAddress);
                                        break;
                                }
                            }
                            break;

                        case (ushort)SctpInitChunkParameterType.EcnCapable:
                            break;

                        case (ushort)SctpInitChunkParameterType.StateCookie:

                            initChunk.StateCookie = varParam.ParameterValue;
                            break;

                        case (ushort)SctpInitChunkParameterType.UnrecognizedParameter:


                            initChunk.UnrecognizedParameters.Add(varParam.ParameterValue);
                            break;

                        default:

                            initChunk.GotUnrecognisedParameter(varParam);
                            break;
                    }

                    if (stopProcessing)
                    {
                        logger.LogWarning("SCTP unrecognised parameter {ParameterType} for chunk type {ChunkType} indicated no further chunks should be processed.", varParam.ParameterType, initChunk.KnownType);
                        break;
                    }
                }
            }

            return initChunk;
        }
    }
}
