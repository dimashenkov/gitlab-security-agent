#nullable enable
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet.Common;

namespace Renci.SshNet
{



    public interface IBaseClient : IDisposable
    {







        ConnectionInfo ConnectionInfo { get; }








        bool IsConnected { get; }









        TimeSpan KeepAliveInterval { get; set; }




        event EventHandler<ExceptionEventArgs> ErrorOccurred;




        event EventHandler<HostKeyEventArgs> HostKeyReceived;




        event EventHandler<SshIdentificationEventArgs>? ServerIdentificationReceived;










        void Connect();













        Task ConnectAsync(CancellationToken cancellationToken);





        void Disconnect();









        void SendKeepAlive();
    }
}
