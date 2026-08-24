#nullable enable
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using Renci.SshNet.Common;
using Renci.SshNet.Messages.Transport;

namespace Renci.SshNet
{



    public abstract class BaseClient : IBaseClient
    {



        private readonly bool _ownsConnectionInfo;

        private readonly ILogger _logger;
        private readonly IServiceFactory _serviceFactory;
        private readonly object _keepAliveLock = new object();
        private TimeSpan _keepAliveInterval;
        private Timer? _keepAliveTimer;
        private ConnectionInfo _connectionInfo;
        private bool _isDisposed;







        internal ISession? Session { get; private set; }







        internal IServiceFactory ServiceFactory
        {
            get { return _serviceFactory; }
        }








        public ConnectionInfo ConnectionInfo
        {
            get
            {
                CheckDisposed();
                return _connectionInfo;
            }
            private set
            {
                _connectionInfo = value;
            }
        }








        public virtual bool IsConnected
        {
            get
            {
                CheckDisposed();

                return IsSessionConnected();
            }
        }









        public TimeSpan KeepAliveInterval
        {
            get
            {
                CheckDisposed();
                return _keepAliveInterval;
            }
            set
            {
                CheckDisposed();

                value.EnsureValidTimeout(nameof(KeepAliveInterval));

                if (value == _keepAliveInterval)
                {
                    return;
                }

                if (value == Timeout.InfiniteTimeSpan)
                {

                    StopKeepAliveTimer();
                }
                else
                {
                    if (_keepAliveTimer != null)
                    {


                        _ = _keepAliveTimer.Change(value, value);
                    }
                    else if (IsSessionConnected())
                    {





                        _keepAliveTimer = CreateKeepAliveTimer(value, value);
                    }



                }

                _keepAliveInterval = value;
            }
        }




        public event EventHandler<ExceptionEventArgs>? ErrorOccurred;




        public event EventHandler<HostKeyEventArgs>? HostKeyReceived;




        public event EventHandler<SshIdentificationEventArgs>? ServerIdentificationReceived;











        protected BaseClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo)
            : this(connectionInfo, ownsConnectionInfo, new ServiceFactory())
        {
        }













        private protected BaseClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo, IServiceFactory serviceFactory)
        {
            ArgumentNullException.ThrowIfNull(connectionInfo);
            ArgumentNullException.ThrowIfNull(serviceFactory);

            _connectionInfo = connectionInfo;
            _ownsConnectionInfo = ownsConnectionInfo;
            _serviceFactory = serviceFactory;
            _logger = (connectionInfo.LoggerFactory ?? SshNetLoggingConfiguration.LoggerFactory).CreateLogger(GetType());
            _keepAliveInterval = Timeout.InfiniteTimeSpan;
        }










        public void Connect()
        {
            CheckDisposed();

















            if (IsConnected)
            {
                throw new InvalidOperationException("The client is already connected.");
            }

            OnConnecting();


            var session = Session;
            if (session is null || !session.IsConnected)
            {
                if (session is not null)
                {
                    DisposeSession(session);
                }

                Session = CreateAndConnectSession();
            }

            try
            {


                OnConnected();
            }
            catch
            {


                DisposeSession();
                throw;
            }

            StartKeepAliveTimer();
        }













        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            CheckDisposed();
            cancellationToken.ThrowIfCancellationRequested();

















            if (IsConnected)
            {
                throw new InvalidOperationException("The client is already connected.");
            }

            OnConnecting();


            var session = Session;
            if (session is null || !session.IsConnected)
            {
                if (session is not null)
                {
                    DisposeSession(session);
                }

                using var timeoutCancellationTokenSource = new CancellationTokenSource(ConnectionInfo.Timeout);
                using var linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellationTokenSource.Token);

                try
                {
                    Session = await CreateAndConnectSessionAsync(linkedCancellationTokenSource.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException ex) when (timeoutCancellationTokenSource.IsCancellationRequested)
                {
                    throw new SshOperationTimeoutException("Connection has timed out.", ex);
                }
            }

            try
            {


                OnConnected();
            }
            catch
            {


                DisposeSession();
                throw;
            }

            StartKeepAliveTimer();
        }





        public void Disconnect()
        {
            _logger.LogInformation("Disconnecting client.");

            CheckDisposed();

            OnDisconnecting();


            StopKeepAliveTimer();


            DisposeSession();

            OnDisconnected();
        }









#pragma warning disable S1133
        [Obsolete("Use KeepAliveInterval to send a keep-alive message at regular intervals.")]
#pragma warning restore S1133
        public void SendKeepAlive()
        {
            CheckDisposed();

            SendKeepAliveMessage();
        }




        protected virtual void OnConnecting()
        {
        }




        protected virtual void OnConnected()
        {
        }




        protected virtual void OnDisconnecting()
        {
            Session?.OnDisconnecting();
        }




        protected virtual void OnDisconnected()
        {
        }

        private void Session_ErrorOccurred(object? sender, ExceptionEventArgs e)
        {
            ErrorOccurred?.Invoke(this, e);
        }

        private void Session_HostKeyReceived(object? sender, HostKeyEventArgs e)
        {
            HostKeyReceived?.Invoke(this, e);
        }

        private void Session_ServerIdentificationReceived(object? sender, SshIdentificationEventArgs e)
        {
            ServerIdentificationReceived?.Invoke(this, e);
        }




        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }





        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
            {
                return;
            }

            if (disposing)
            {
                _logger.LogDebug("Disposing client.");

                Disconnect();

                if (_ownsConnectionInfo)
                {
                    if (_connectionInfo is IDisposable connectionInfoDisposable)
                    {
                        connectionInfoDisposable.Dispose();
                    }
                }

                _isDisposed = true;
            }
        }





        protected void CheckDisposed()
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
        }





        private void StopKeepAliveTimer()
        {
            if (_keepAliveTimer is null)
            {
                return;
            }

            _keepAliveTimer.Dispose();
            _keepAliveTimer = null;
        }

        private void SendKeepAliveMessage()
        {
            var session = Session;


            if (session is null)
            {
                return;
            }


            if (Monitor.TryEnter(_keepAliveLock))
            {
                try
                {
                    _ = session.TrySendMessage(new IgnoreMessage());
                }
                catch (ObjectDisposedException)
                {

                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error sending keepalive message");
                }
                finally
                {
                    Monitor.Exit(_keepAliveLock);
                }
            }
        }








        private void StartKeepAliveTimer()
        {
            if (_keepAliveInterval == Timeout.InfiniteTimeSpan)
            {
                return;
            }

            if (_keepAliveTimer != null)
            {

                return;
            }

            _keepAliveTimer = CreateKeepAliveTimer(_keepAliveInterval, _keepAliveInterval);
        }









        private Timer CreateKeepAliveTimer(TimeSpan dueTime, TimeSpan period)
        {
            return new Timer(state => SendKeepAliveMessage(), Session, dueTime, period);
        }

        private ISession CreateAndConnectSession()
        {
            var session = _serviceFactory.CreateSession(ConnectionInfo, _serviceFactory.CreateSocketFactory());
            session.ServerIdentificationReceived += Session_ServerIdentificationReceived;
            session.HostKeyReceived += Session_HostKeyReceived;
            session.ErrorOccured += Session_ErrorOccurred;

            try
            {
                session.Connect();
                return session;
            }
            catch
            {
                DisposeSession(session);
                throw;
            }
        }

        private async Task<ISession> CreateAndConnectSessionAsync(CancellationToken cancellationToken)
        {
            var session = _serviceFactory.CreateSession(ConnectionInfo, _serviceFactory.CreateSocketFactory());
            session.ServerIdentificationReceived += Session_ServerIdentificationReceived;
            session.HostKeyReceived += Session_HostKeyReceived;
            session.ErrorOccured += Session_ErrorOccurred;

            try
            {
                await session.ConnectAsync(cancellationToken).ConfigureAwait(false);
                return session;
            }
            catch
            {
                DisposeSession(session);
                throw;
            }
        }

        private void DisposeSession(ISession session)
        {
            session.ErrorOccured -= Session_ErrorOccurred;
            session.HostKeyReceived -= Session_HostKeyReceived;
            session.ServerIdentificationReceived -= Session_ServerIdentificationReceived;
            session.Dispose();
        }




        private void DisposeSession()
        {
            var session = Session;
            if (session != null)
            {
                Session = null;
                DisposeSession(session);
            }
        }







        private bool IsSessionConnected()
        {
            var session = Session;
            return session != null && session.IsConnected;
        }
    }
}
