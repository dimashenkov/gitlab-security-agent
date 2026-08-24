

































using System;

namespace SIPSorcery.Net
{
    public delegate void OnDataChannelMessageDelegate(RTCDataChannel dc, DataChannelPayloadProtocols protocol, byte[] data);

    public enum RTCDataChannelState
    {





        connecting,




        open,




        closing,




        closed
    };







    interface IRTCDataChannel
    {





        string label { get; }





        bool ordered { get; }






        ushort? maxPacketLifeTime { get; }





        ushort? maxRetransmits { get; }





        string protocol { get; }





        bool negotiated { get; }








        ushort? id { get; }





        RTCDataChannelState readyState { get; }











        ulong bufferedAmount { get; }






        ulong bufferedAmountLowThreshold { get; set; }




        event Action onopen;


        event Action<string> onerror;

        event Action onclose;
        void close();




        event OnDataChannelMessageDelegate onmessage;

        string binaryType { get; set; }
        void send(string data);
        void send(byte[] data, int offset = 0, int count = -1);
    };

    public class RTCDataChannelInit
    {
        public bool? ordered { get; set; }
        public ushort? maxPacketLifeTime { get; set; }
        public ushort? maxRetransmits { get; set; }
        public string protocol { get; set; }
        public bool? negotiated { get; set; }
        public ushort? id { get; set; }
    };
}
