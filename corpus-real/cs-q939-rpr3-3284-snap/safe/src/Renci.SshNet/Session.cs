using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using Renci.SshNet.Abstractions;
using Renci.SshNet.Channels;
using Renci.SshNet.Common;
using Renci.SshNet.Compression;
using Renci.SshNet.Connection;
using Renci.SshNet.Messages;
using Renci.SshNet.Messages.Authentication;
using Renci.SshNet.Messages.Connection;
using Renci.SshNet.Messages.Transport;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace Renci.SshNet
{



    public sealed class Session : ISession
    {
        internal const byte CarriageReturn = 0x0d;
        internal const byte LineFeed = 0x0a;







        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize + 3000;










        private const int InitialLocalWindowSize = 0x7FFFFFFF;
















        private const int LocalChannelDataPacketSize = 1024 * 64;

        internal static readonly string ClientVersionString =
            "SSH-2.0-Renci.SshNet.SshClient." + ThisAssembly.NuGetPackageVersion.Replace('-', '_');




        private readonly IServiceFactory _serviceFactory;
        private readonly ISocketFactory _socketFactory;
        private readonly ILogger _logger;









        private readonly Lock _socketWriteLock = new Lock();









        private readonly Lock _socketDisposeLock = new Lock();





        private readonly SemaphoreSlim _connectLock = new SemaphoreSlim(1, 1);

        private readonly byte[] _inboundPacketSequenceBytes = new byte[4];




        private uint InboundPacketSequence
        {
            get
            {
                return BinaryPrimitives.ReadUInt32BigEndian(_inboundPacketSequenceBytes);
            }
            set
            {
                BinaryPrimitives.WriteUInt32BigEndian(_inboundPacketSequenceBytes, value);
            }
        }




        private SshMessageFactory _sshMessageFactory;




        private ManualResetEvent _messageListenerCompleted;




        private volatile uint _outboundPacketSequence;




        private EventWaitHandle _serviceAccepted = new AutoResetEvent(initialState: false);




        private EventWaitHandle _exceptionWaitHandle = new ManualResetEvent(initialState: false);




        private ManualResetEventSlim _keyExchangeCompletedWaitHandle = new ManualResetEventSlim(initialState: false);




        private Exception _exception;




        private bool _isAuthenticated;




        private bool _isDisconnecting;




        private bool _isInitialKex;





        private bool _isStrictKex;

        private IKeyExchange _keyExchange;

        private HashAlgorithm _serverMac;

        private HashAlgorithm _clientMac;

        private bool _serverEtm;

        private bool _clientEtm;

        private Cipher _serverCipher;

        private Cipher _clientCipher;

        private bool _serverAead;

        private bool _clientAead;

        private Compressor _serverDecompression;

        private Compressor _clientCompression;

        private SemaphoreSlim _sessionSemaphore;

        private bool _isDisconnectMessageSent;

        private int _nextChannelNumber;




        private Socket _socket;

        private ArrayBuffer _receiveBuffer = new(4 * 1024);
        private byte[] _sendBuffer = new byte[4 * 1024];







        public SemaphoreSlim SessionSemaphore
        {
            get
            {
                if (_sessionSemaphore is SemaphoreSlim sessionSemaphore)
                {
                    return sessionSemaphore;
                }

                sessionSemaphore = new SemaphoreSlim(ConnectionInfo.MaxSessions);

                if (Interlocked.CompareExchange(ref _sessionSemaphore, sessionSemaphore, comparand: null) is not null)
                {

                    Debug.Assert(_sessionSemaphore != sessionSemaphore);
                    sessionSemaphore.Dispose();
                }

                return _sessionSemaphore;
            }
        }







        private uint NextChannelNumber
        {
            get
            {
                return (uint)Interlocked.Increment(ref _nextChannelNumber);
            }
        }



























        public bool IsConnected
        {
            get
            {
                return !_disposed &&
                    !_isDisconnectMessageSent &&
                    _isAuthenticated &&
                    _messageListenerCompleted?.WaitOne(0) == false &&
                    _socket.IsConnected();
            }
        }

        private byte[] _sessionId;







        public byte[] SessionId
        {
            get
            {
                return _sessionId;
            }
            private set
            {
                _sessionId = value;
                SessionIdHex = value == null ? null : Convert.ToHexString(value);
            }
        }

        internal string SessionIdHex { get; private set; }





        public KeyExchangeInitMessage ClientInitMessage { get; private set; }







        public string ServerVersion { get; private set; }







        public string ClientVersion
        {
            get
            {
                return ClientVersionString;
            }
        }







        public ConnectionInfo ConnectionInfo { get; private set; }







        public ILoggerFactory SessionLoggerFactory { get; }





        public event EventHandler<ExceptionEventArgs> ErrorOccured;




        public event EventHandler<EventArgs> Disconnected;




        public event EventHandler<SshIdentificationEventArgs> ServerIdentificationReceived;




        public event EventHandler<HostKeyEventArgs> HostKeyReceived;




        public event EventHandler<MessageEventArgs<BannerMessage>> UserAuthenticationBannerReceived;




        internal event EventHandler<MessageEventArgs<InformationRequestMessage>> UserAuthenticationInformationRequestReceived;




        internal event EventHandler<MessageEventArgs<PasswordChangeRequiredMessage>> UserAuthenticationPasswordChangeRequiredReceived;




        internal event EventHandler<MessageEventArgs<PublicKeyMessage>> UserAuthenticationPublicKeyReceived;




        internal event EventHandler<MessageEventArgs<KeyExchangeDhGroupExchangeGroup>> KeyExchangeDhGroupExchangeGroupReceived;




        internal event EventHandler<MessageEventArgs<KeyExchangeDhGroupExchangeReply>> KeyExchangeDhGroupExchangeReplyReceived;




        internal event EventHandler<MessageEventArgs<DisconnectMessage>> DisconnectReceived;




        internal event EventHandler<MessageEventArgs<IgnoreMessage>> IgnoreReceived;




        internal event EventHandler<MessageEventArgs<UnimplementedMessage>> UnimplementedReceived;




        internal event EventHandler<MessageEventArgs<DebugMessage>> DebugReceived;




        internal event EventHandler<MessageEventArgs<ServiceRequestMessage>> ServiceRequestReceived;




        internal event EventHandler<MessageEventArgs<ServiceAcceptMessage>> ServiceAcceptReceived;




        internal event EventHandler<MessageEventArgs<KeyExchangeInitMessage>> KeyExchangeInitReceived;




        internal event EventHandler<MessageEventArgs<KeyExchangeDhReplyMessage>> KeyExchangeDhReplyMessageReceived;




        internal event EventHandler<MessageEventArgs<KeyExchangeEcdhReplyMessage>> KeyExchangeEcdhReplyMessageReceived;




        internal event EventHandler<MessageEventArgs<KeyExchangeHybridReplyMessage>> KeyExchangeHybridReplyMessageReceived;




        internal event EventHandler<MessageEventArgs<NewKeysMessage>> NewKeysReceived;




        internal event EventHandler<MessageEventArgs<RequestMessage>> UserAuthenticationRequestReceived;




        internal event EventHandler<MessageEventArgs<FailureMessage>> UserAuthenticationFailureReceived;




        internal event EventHandler<MessageEventArgs<SuccessMessage>> UserAuthenticationSuccessReceived;




        public event EventHandler<MessageEventArgs<RequestSuccessMessage>> RequestSuccessReceived;




        public event EventHandler<MessageEventArgs<RequestFailureMessage>> RequestFailureReceived;




        public event EventHandler<MessageEventArgs<ChannelOpenMessage>> ChannelOpenReceived;




        public event EventHandler<MessageEventArgs<ChannelOpenConfirmationMessage>> ChannelOpenConfirmationReceived;




        public event EventHandler<MessageEventArgs<ChannelOpenFailureMessage>> ChannelOpenFailureReceived;




        public event EventHandler<MessageEventArgs<ChannelWindowAdjustMessage>> ChannelWindowAdjustReceived;




        public event EventHandler<MessageEventArgs<ChannelDataMessage>> ChannelDataReceived;




        public event EventHandler<MessageEventArgs<ChannelExtendedDataMessage>> ChannelExtendedDataReceived;




        public event EventHandler<MessageEventArgs<ChannelEofMessage>> ChannelEofReceived;




        public event EventHandler<MessageEventArgs<ChannelCloseMessage>> ChannelCloseReceived;




        public event EventHandler<MessageEventArgs<ChannelRequestMessage>> ChannelRequestReceived;




        public event EventHandler<MessageEventArgs<ChannelSuccessMessage>> ChannelSuccessReceived;




        public event EventHandler<MessageEventArgs<ChannelFailureMessage>> ChannelFailureReceived;










        internal Session(ConnectionInfo connectionInfo, IServiceFactory serviceFactory, ISocketFactory socketFactory)
        {
            ArgumentNullException.ThrowIfNull(connectionInfo);
            ArgumentNullException.ThrowIfNull(serviceFactory);
            ArgumentNullException.ThrowIfNull(socketFactory);

            ConnectionInfo = connectionInfo;
            SessionLoggerFactory = connectionInfo.LoggerFactory ?? SshNetLoggingConfiguration.LoggerFactory;
            _serviceFactory = serviceFactory;
            _socketFactory = socketFactory;
            _logger = SessionLoggerFactory.CreateLogger<Session>();
            _messageListenerCompleted = new ManualResetEvent(initialState: true);
        }








        public void Connect()
        {
            if (IsConnected)
            {
                return;
            }

            _connectLock.Wait();

            try
            {
                if (IsConnected)
                {
                    return;
                }


                Reset();


                _sshMessageFactory = new SshMessageFactory();

                _socket = _serviceFactory.CreateConnector(ConnectionInfo, _socketFactory)
                                            .Connect(ConnectionInfo);

                var serverIdentification = _serviceFactory.CreateProtocolVersionExchange()
                                                            .Start(ClientVersion, _socket, ConnectionInfo.Timeout);


                ServerVersion = ConnectionInfo.ServerVersion = serverIdentification.ToString();

                _logger.LogInformation("Server version '{ServerIdentification}'.", serverIdentification);

                if (!(serverIdentification.ProtocolVersion.Equals("2.0") || serverIdentification.ProtocolVersion.Equals("1.99")))
                {
                    throw new SshConnectionException(string.Format(CultureInfo.CurrentCulture, "Server version '{0}' is not supported.", serverIdentification.ProtocolVersion),
                                                        DisconnectReason.ProtocolVersionNotSupported);
                }

                ServerIdentificationReceived?.Invoke(this, new SshIdentificationEventArgs(serverIdentification));


                RegisterMessage("SSH_MSG_DISCONNECT");
                RegisterMessage("SSH_MSG_IGNORE");
                RegisterMessage("SSH_MSG_UNIMPLEMENTED");
                RegisterMessage("SSH_MSG_DEBUG");
                RegisterMessage("SSH_MSG_SERVICE_ACCEPT");
                RegisterMessage("SSH_MSG_KEXINIT");
                RegisterMessage("SSH_MSG_NEWKEYS");


                RegisterMessage("SSH_MSG_USERAUTH_BANNER");




                _isInitialKex = true;
                ClientInitMessage = BuildClientInitMessage(includeStrictKexPseudoAlgorithm: true);
                SendMessage(ClientInitMessage);


                _ = _messageListenerCompleted.Reset();



                _ = ThreadAbstraction.ExecuteThreadLongRunning(MessageListener);


                WaitOnHandle(_keyExchangeCompletedWaitHandle.WaitHandle);


                if (SessionId is null)
                {
                    Disconnect();
                    return;
                }


                SendMessage(new ServiceRequestMessage(ServiceName.UserAuthentication));


                WaitOnHandle(_serviceAccepted);

                if (string.IsNullOrEmpty(ConnectionInfo.Username))
                {
                    throw new SshException("Username is not specified.");
                }



                RegisterMessage("SSH_MSG_GLOBAL_REQUEST");

                ConnectionInfo.Authenticate(this, _serviceFactory);
                _isAuthenticated = true;


                RegisterMessage("SSH_MSG_REQUEST_SUCCESS");
                RegisterMessage("SSH_MSG_REQUEST_FAILURE");
                RegisterMessage("SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
                RegisterMessage("SSH_MSG_CHANNEL_OPEN_FAILURE");
                RegisterMessage("SSH_MSG_CHANNEL_WINDOW_ADJUST");
                RegisterMessage("SSH_MSG_CHANNEL_EXTENDED_DATA");
                RegisterMessage("SSH_MSG_CHANNEL_REQUEST");
                RegisterMessage("SSH_MSG_CHANNEL_SUCCESS");
                RegisterMessage("SSH_MSG_CHANNEL_FAILURE");
                RegisterMessage("SSH_MSG_CHANNEL_DATA");
                RegisterMessage("SSH_MSG_CHANNEL_EOF");
                RegisterMessage("SSH_MSG_CHANNEL_CLOSE");
            }
            finally
            {
                _ = _connectLock.Release();
            }
        }










        public async Task ConnectAsync(CancellationToken cancellationToken)
        {

            if (IsConnected)
            {
                return;
            }

            await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                if (IsConnected)
                {
                    return;
                }


                Reset();


                _sshMessageFactory = new SshMessageFactory();

                _socket = await _serviceFactory.CreateConnector(ConnectionInfo, _socketFactory)
                                            .ConnectAsync(ConnectionInfo, cancellationToken).ConfigureAwait(false);

                var serverIdentification = await _serviceFactory.CreateProtocolVersionExchange()
                                                            .StartAsync(ClientVersion, _socket, cancellationToken).ConfigureAwait(false);


                ServerVersion = ConnectionInfo.ServerVersion = serverIdentification.ToString();

                _logger.LogInformation("Server version '{ServerIdentification}'.", serverIdentification);

                if (!(serverIdentification.ProtocolVersion.Equals("2.0") || serverIdentification.ProtocolVersion.Equals("1.99")))
                {
                    throw new SshConnectionException(string.Format(CultureInfo.CurrentCulture, "Server version '{0}' is not supported.", serverIdentification.ProtocolVersion),
                                                        DisconnectReason.ProtocolVersionNotSupported);
                }

                ServerIdentificationReceived?.Invoke(this, new SshIdentificationEventArgs(serverIdentification));


                RegisterMessage("SSH_MSG_DISCONNECT");
                RegisterMessage("SSH_MSG_IGNORE");
                RegisterMessage("SSH_MSG_UNIMPLEMENTED");
                RegisterMessage("SSH_MSG_DEBUG");
                RegisterMessage("SSH_MSG_SERVICE_ACCEPT");
                RegisterMessage("SSH_MSG_KEXINIT");
                RegisterMessage("SSH_MSG_NEWKEYS");


                RegisterMessage("SSH_MSG_USERAUTH_BANNER");




                _isInitialKex = true;
                ClientInitMessage = BuildClientInitMessage(includeStrictKexPseudoAlgorithm: true);
                SendMessage(ClientInitMessage);


                _ = _messageListenerCompleted.Reset();



                _ = ThreadAbstraction.ExecuteThreadLongRunning(MessageListener);


                WaitOnHandle(_keyExchangeCompletedWaitHandle.WaitHandle);


                if (SessionId is null)
                {
                    Disconnect();
                    return;
                }


                SendMessage(new ServiceRequestMessage(ServiceName.UserAuthentication));


                WaitOnHandle(_serviceAccepted);

                if (string.IsNullOrEmpty(ConnectionInfo.Username))
                {
                    throw new SshException("Username is not specified.");
                }



                RegisterMessage("SSH_MSG_GLOBAL_REQUEST");

                ConnectionInfo.Authenticate(this, _serviceFactory);
                _isAuthenticated = true;


                RegisterMessage("SSH_MSG_REQUEST_SUCCESS");
                RegisterMessage("SSH_MSG_REQUEST_FAILURE");
                RegisterMessage("SSH_MSG_CHANNEL_OPEN_CONFIRMATION");
                RegisterMessage("SSH_MSG_CHANNEL_OPEN_FAILURE");
                RegisterMessage("SSH_MSG_CHANNEL_WINDOW_ADJUST");
                RegisterMessage("SSH_MSG_CHANNEL_EXTENDED_DATA");
                RegisterMessage("SSH_MSG_CHANNEL_REQUEST");
                RegisterMessage("SSH_MSG_CHANNEL_SUCCESS");
                RegisterMessage("SSH_MSG_CHANNEL_FAILURE");
                RegisterMessage("SSH_MSG_CHANNEL_DATA");
                RegisterMessage("SSH_MSG_CHANNEL_EOF");
                RegisterMessage("SSH_MSG_CHANNEL_CLOSE");
            }
            finally
            {
                _ = _connectLock.Release();
            }
        }








        public void Disconnect()
        {
            _logger.LogInformation("[{SessionId}] Disconnecting session.", SessionIdHex);


            Disconnect(DisconnectReason.ByApplication, "Connection terminated by the client.");




            if (_messageListenerCompleted != null)
            {
                _ = _messageListenerCompleted.WaitOne();
            }
        }

        private void Disconnect(DisconnectReason reason, string message)
        {


            _isDisconnecting = true;






            if (IsConnected)
            {
                TrySendDisconnect(reason, message);
            }


            SocketDisconnectAndDispose();
        }













        void ISession.WaitOnHandle(WaitHandle waitHandle)
        {
            WaitOnHandle(waitHandle, ConnectionInfo.Timeout);
        }














        void ISession.WaitOnHandle(WaitHandle waitHandle, TimeSpan timeout)
        {
            WaitOnHandle(waitHandle, timeout);
        }










        WaitResult ISession.TryWait(WaitHandle waitHandle, TimeSpan timeout)
        {
            return TryWait(waitHandle, timeout, out _);
        }











        WaitResult ISession.TryWait(WaitHandle waitHandle, TimeSpan timeout, out Exception exception)
        {
            return TryWait(waitHandle, timeout, out exception);
        }











        private WaitResult TryWait(WaitHandle waitHandle, TimeSpan timeout, out Exception exception)
        {
            ArgumentNullException.ThrowIfNull(waitHandle);

            var waitHandles = new[]
                {
                    _exceptionWaitHandle,
                    _messageListenerCompleted,
                    waitHandle
                };

            switch (WaitHandle.WaitAny(waitHandles, timeout))
            {
                case 0:
                    if (_exception is SshConnectionException)
                    {
                        exception = null;
                        return WaitResult.Disconnected;
                    }

                    exception = _exception;
                    return WaitResult.Failed;
                case 1:
                    exception = null;
                    return WaitResult.Disconnected;
                case 2:
                    exception = null;
                    return WaitResult.Success;
                case WaitHandle.WaitTimeout:
                    exception = null;
                    return WaitResult.TimedOut;
                default:
                    throw new InvalidOperationException("Unexpected result.");
            }
        }













        internal void WaitOnHandle(WaitHandle waitHandle)
        {
            WaitOnHandle(waitHandle, ConnectionInfo.Timeout);
        }










        internal void WaitOnHandle(WaitHandle waitHandle, TimeSpan timeout)
        {
            ArgumentNullException.ThrowIfNull(waitHandle);

            var waitHandles = new[]
                {
                    _exceptionWaitHandle,
                    _messageListenerCompleted,
                    waitHandle
                };

            var signaledElement = WaitHandle.WaitAny(waitHandles, timeout);
            switch (signaledElement)
            {
                case 0:
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(_exception).Throw();
                    break;
                case 1:
                    throw new SshConnectionException("Client not connected.");
                case 2:

                    break;
                case WaitHandle.WaitTimeout:






                    if (!_isDisconnecting)
                    {
                        throw new SshOperationTimeoutException("Session operation has timed out");
                    }

                    break;
                default:
                    throw new SshException($"Unexpected element '{signaledElement.ToString(CultureInfo.InvariantCulture)}' signaled.");
            }
        }








        internal void SendMessage(Message message)
        {
            if (!_socket.IsConnected())
            {
                throw new SshConnectionException("Client not connected.");
            }

            if (!_keyExchangeCompletedWaitHandle.IsSet && message is not IKeyExchangedAllowed)
            {

                WaitOnHandle(_keyExchangeCompletedWaitHandle.WaitHandle);
            }

            if (_logger.IsEnabled(LogLevel.Trace))
            {
                _logger.LogTrace("[{SessionId}] Sending message {MessageName}({MessageNumber}) to server: '{Message}'.", SessionIdHex, message.MessageName, message.MessageNumber, message.ToString());
            }

            var paddingMultiplier = _clientCipher is null ? (byte)8 : Math.Max((byte)8, _clientCipher.MinimumSize);

            var macLength = 0;

            if (_clientAead)
            {
                macLength = _clientCipher.TagSize;
            }
            else if (_clientMac != null)
            {
                macLength = _clientMac.HashSize / 8;
            }



            lock (_socketWriteLock)
            {
                var activeBufferLength = message.GetPacket(
                    ref _sendBuffer,
                    paddingMultiplier,
                    _clientCompression,
                    _clientEtm || _clientAead,
                    macLength);


                BinaryPrimitives.WriteUInt32BigEndian(_sendBuffer, _outboundPacketSequence);

                if (_clientMac != null && !_clientEtm)
                {


                    var hashSuccess = _clientMac.TryComputeHash(
                        buffer: _sendBuffer,
                        offset: 0,
                        count: activeBufferLength - macLength,
                        destination: _sendBuffer.AsSpan(activeBufferLength - macLength),
                        bytesWritten: out var bytesWritten);

                    Debug.Assert(hashSuccess && bytesWritten == macLength);
                }

                if (_clientCipher != null)
                {
                    _clientCipher.SetSequenceNumber(_outboundPacketSequence);



                    var offset = _clientEtm ? 8 : 4;

                    var numberOfBytesEncrypted = _clientCipher.Encrypt(
                        input: _sendBuffer,
                        offset,
                        length: activeBufferLength - offset - macLength,
                        output: _sendBuffer,
                        outputOffset: offset);

                    Debug.Assert(numberOfBytesEncrypted == activeBufferLength - offset - macLength + (_clientAead ? macLength : 0));
                }

                if (_clientMac != null && _clientEtm)
                {


                    var hashSuccess = _clientMac.TryComputeHash(
                        buffer: _sendBuffer,
                        offset: 0,
                        count: activeBufferLength - macLength,
                        destination: _sendBuffer.AsSpan(activeBufferLength - macLength),
                        bytesWritten: out var bytesWritten);

                    Debug.Assert(hashSuccess && bytesWritten == macLength);
                }

                SendPacket(_sendBuffer, 4, activeBufferLength - 4);

                if (_isStrictKex && message is NewKeysMessage)
                {
                    _outboundPacketSequence = 0;
                }
                else
                {






                    _outboundPacketSequence++;
                }
            }
        }


















        private void SendPacket(byte[] packet, int offset, int length)
        {
            lock (_socketDisposeLock)
            {
                if (!_socket.IsConnected())
                {
                    throw new SshConnectionException("Client not connected.");
                }

                SocketAbstraction.Send(_socket, packet, offset, length);
            }
        }













        private bool TrySendMessage(Message message)
        {
            try
            {
                SendMessage(message);
                return true;
            }
            catch (SshException ex)
            {
                _logger.LogInformation(ex, "Failure sending message {MessageName}({MessageNumber}) to server: '{Message}'", message.MessageName, message.MessageNumber, message.ToString());
                return false;
            }
            catch (SocketException ex)
            {
                _logger.LogInformation(ex, "Failure sending message {MessageName}({MessageNumber}) to server: '{Message}'", message.MessageName, message.MessageNumber, message.ToString());
                return false;
            }
        }










        private Message ReceiveMessage(Socket socket)
        {

            const int packetLengthFieldLength = 4;


            const int paddingLengthFieldLength = 1;

            int blockSize;



            if (_serverEtm || _serverAead)
            {
                blockSize = (byte)4;
            }
            else if (_serverCipher != null)
            {
                blockSize = Math.Max((byte)8, _serverCipher.MinimumSize);
            }
            else
            {
                blockSize = (byte)8;
            }

            var serverMacLength = 0;

            if (_serverAead)
            {
                serverMacLength = _serverCipher.TagSize;
            }
            else if (_serverMac != null)
            {
                serverMacLength = _serverMac.HashSize / 8;
            }

            if (_receiveBuffer.ActiveLength < blockSize)
            {
                var bytesNeeded = blockSize - _receiveBuffer.ActiveLength;

                _receiveBuffer.EnsureAvailableSpace(bytesNeeded);

                var bytesRead = TrySocketRead(
                    socket,
                    buffer: _receiveBuffer.DangerousGetUnderlyingBuffer(),
                    offset: _receiveBuffer.ActiveStartOffset + _receiveBuffer.ActiveLength,
                    length: _receiveBuffer.AvailableLength,
                    minimumLength: bytesNeeded);

                _receiveBuffer.Commit(bytesRead);

                if (bytesRead < bytesNeeded)
                {

                    return null;
                }
            }







            if (_serverCipher is not null and not Security.Cryptography.Ciphers.AesGcmCipher)
            {
                _serverCipher.SetSequenceNumber(InboundPacketSequence);

                if (_serverMac == null || !_serverEtm)
                {
                    var plainFirstBlock = _serverCipher.Decrypt(
                        _receiveBuffer.DangerousGetUnderlyingBuffer(),
                        _receiveBuffer.ActiveStartOffset,
                        blockSize);

                    plainFirstBlock.CopyTo(_receiveBuffer.ActiveSpan);
                }
            }

            var packetLength = BinaryPrimitives.ReadInt32BigEndian(_receiveBuffer.ActiveReadOnlySpan);


            if (packetLength < Math.Max((byte)8, blockSize) - 4 || packetLength > MaximumSshPacketSize - 4)
            {
                throw new SshConnectionException(
                    string.Format(CultureInfo.CurrentCulture, "Bad packet length: {0}.", (uint)packetLength),
                    DisconnectReason.ProtocolError);
            }

            var totalPacketLength = 4 + packetLength + serverMacLength;

            if (_receiveBuffer.ActiveLength < totalPacketLength)
            {
                var bytesNeeded = totalPacketLength - _receiveBuffer.ActiveLength;

                _receiveBuffer.EnsureAvailableSpace(bytesNeeded);

                var bytesRead = TrySocketRead(
                    socket,
                    buffer: _receiveBuffer.DangerousGetUnderlyingBuffer(),
                    offset: _receiveBuffer.ActiveStartOffset + _receiveBuffer.ActiveLength,
                    length: _receiveBuffer.AvailableLength,
                    minimumLength: bytesNeeded);

                _receiveBuffer.Commit(bytesRead);

                if (bytesRead < bytesNeeded)
                {

                    return null;
                }
            }

            if (_serverMac != null && _serverEtm)
            {



                _ = _serverMac.TransformBlock(
                    inputBuffer: _inboundPacketSequenceBytes,
                    inputOffset: 0,
                    inputCount: 4,
                    outputBuffer: null,
                    outputOffset: 0);


                _ = _serverMac.TransformBlock(
                    inputBuffer: _receiveBuffer.DangerousGetUnderlyingBuffer(),
                    inputOffset: _receiveBuffer.ActiveStartOffset,
                    inputCount: totalPacketLength - serverMacLength,
                    outputBuffer: null,
                    outputOffset: 0);

                _ = _serverMac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                if (!CryptoAbstraction.FixedTimeEquals(_serverMac.Hash, _receiveBuffer.ActiveSpan.Slice(totalPacketLength - serverMacLength, serverMacLength)))
                {
                    throw new SshConnectionException("MAC error", DisconnectReason.MacError);
                }
            }

            var numberOfBytesToDecrypt = 4 + packetLength - blockSize;

            if (_serverCipher != null && numberOfBytesToDecrypt > 0)
            {
                Debug.Assert(numberOfBytesToDecrypt % blockSize == 0);

                var decryptBuffer = _receiveBuffer.DangerousGetUnderlyingBuffer();
                var decryptOffset = _receiveBuffer.ActiveStartOffset + blockSize;

                var numberOfBytesDecrypted = _serverCipher.Decrypt(
                    input: decryptBuffer,
                    offset: decryptOffset,
                    length: numberOfBytesToDecrypt,
                    output: decryptBuffer,
                    outputOffset: decryptOffset);

                Debug.Assert(numberOfBytesDecrypted == numberOfBytesToDecrypt);
            }

            if (_serverMac != null && !_serverEtm)
            {



                _ = _serverMac.TransformBlock(
                    inputBuffer: _inboundPacketSequenceBytes,
                    inputOffset: 0,
                    inputCount: 4,
                    outputBuffer: null,
                    outputOffset: 0);


                _ = _serverMac.TransformBlock(
                    inputBuffer: _receiveBuffer.DangerousGetUnderlyingBuffer(),
                    inputOffset: _receiveBuffer.ActiveStartOffset,
                    inputCount: totalPacketLength - serverMacLength,
                    outputBuffer: null,
                    outputOffset: 0);

                _ = _serverMac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                if (!CryptoAbstraction.FixedTimeEquals(_serverMac.Hash, _receiveBuffer.ActiveSpan.Slice(totalPacketLength - serverMacLength, serverMacLength)))
                {
                    throw new SshConnectionException("MAC error", DisconnectReason.MacError);
                }
            }

            var paddingLength = _receiveBuffer.ActiveReadOnlySpan[packetLengthFieldLength];

            ArraySegment<byte> payload = new(
                _receiveBuffer.DangerousGetUnderlyingBuffer(),
                offset: _receiveBuffer.ActiveStartOffset + packetLengthFieldLength + paddingLengthFieldLength,
                count: packetLength - paddingLength - paddingLengthFieldLength);

            if (_serverDecompression != null)
            {
                payload = new(_serverDecompression.Decompress(payload.Array, payload.Offset, payload.Count));
            }

            var newInboundPacketSequence = ++InboundPacketSequence;



            if (newInboundPacketSequence == uint.MaxValue && _isInitialKex)
            {
                throw new SshConnectionException("Inbound packet sequence number is about to wrap during initial key exchange.", DisconnectReason.KeyExchangeFailed);
            }

            var message = LoadMessage(payload.Array, payload.Offset, payload.Count);





            _receiveBuffer.Discard(totalPacketLength);

            return message;
        }

        private void TrySendDisconnect(DisconnectReason reasonCode, string message)
        {
            var disconnectMessage = new DisconnectMessage(reasonCode, message);


            _ = TrySendMessage(disconnectMessage);


            _isDisconnectMessageSent = true;
        }





        internal void OnDisconnectReceived(DisconnectMessage message)
        {
            _logger.LogInformation("[{SessionId}] Disconnect received: {ReasonCode} {MessageDescription}.", SessionIdHex, message.ReasonCode, message.Description);




            _isDisconnecting = true;

            _exception = new SshConnectionException(string.Format(CultureInfo.InvariantCulture, "The connection was closed by the server: {0} ({1}).", message.Description, message.ReasonCode), message.ReasonCode);
            _ = _exceptionWaitHandle.Set();

            DisconnectReceived?.Invoke(this, new MessageEventArgs<DisconnectMessage>(message));

            Disconnected?.Invoke(this, EventArgs.Empty);


            SocketDisconnectAndDispose();
        }





        internal void OnIgnoreReceived(IgnoreMessage message)
        {
            IgnoreReceived?.Invoke(this, new MessageEventArgs<IgnoreMessage>(message));
        }





        internal void OnUnimplementedReceived(UnimplementedMessage message)
        {
            UnimplementedReceived?.Invoke(this, new MessageEventArgs<UnimplementedMessage>(message));
        }





        internal void OnDebugReceived(DebugMessage message)
        {
            DebugReceived?.Invoke(this, new MessageEventArgs<DebugMessage>(message));
        }





        internal void OnServiceRequestReceived(ServiceRequestMessage message)
        {
            ServiceRequestReceived?.Invoke(this, new MessageEventArgs<ServiceRequestMessage>(message));
        }





        internal void OnServiceAcceptReceived(ServiceAcceptMessage message)
        {
            ServiceAcceptReceived?.Invoke(this, new MessageEventArgs<ServiceAcceptMessage>(message));

            _ = _serviceAccepted.Set();
        }

        internal void OnKeyExchangeDhGroupExchangeGroupReceived(KeyExchangeDhGroupExchangeGroup message)
        {
            KeyExchangeDhGroupExchangeGroupReceived?.Invoke(this, new MessageEventArgs<KeyExchangeDhGroupExchangeGroup>(message));
        }

        internal void OnKeyExchangeDhGroupExchangeReplyReceived(KeyExchangeDhGroupExchangeReply message)
        {
            KeyExchangeDhGroupExchangeReplyReceived?.Invoke(this, new MessageEventArgs<KeyExchangeDhGroupExchangeReply>(message));
        }





        internal void OnKeyExchangeInitReceived(KeyExchangeInitMessage message)
        {






            var sendClientInitMessage = _keyExchangeCompletedWaitHandle.IsSet;

            _keyExchangeCompletedWaitHandle.Reset();

            if (_isInitialKex && message.KeyExchangeAlgorithms.Contains("kex-strict-s-v00@openssh.com"))
            {
                _isStrictKex = true;

                _logger.LogDebug("[{SessionId}] Enabling strict key exchange extension.", SessionIdHex);

                if (InboundPacketSequence != 1)
                {
                    throw new SshConnectionException("KEXINIT was not the first packet during strict key exchange.", DisconnectReason.KeyExchangeFailed);
                }
            }


            _sshMessageFactory.DisableNonKeyExchangeMessages(_isStrictKex);

            _keyExchange = _serviceFactory.CreateKeyExchange(ConnectionInfo.KeyExchangeAlgorithms,
                                                             message.KeyExchangeAlgorithms);

            ConnectionInfo.CurrentKeyExchangeAlgorithm = _keyExchange.Name;

            _logger.LogDebug("[{SessionId}] Performing {KeyExchangeAlgorithm} key exchange.", SessionIdHex, ConnectionInfo.CurrentKeyExchangeAlgorithm);

            _keyExchange.HostKeyReceived += KeyExchange_HostKeyReceived;


            _keyExchange.Start(this, message, sendClientInitMessage);

            KeyExchangeInitReceived?.Invoke(this, new MessageEventArgs<KeyExchangeInitMessage>(message));
        }

        internal void OnKeyExchangeDhReplyMessageReceived(KeyExchangeDhReplyMessage message)
        {
            KeyExchangeDhReplyMessageReceived?.Invoke(this, new MessageEventArgs<KeyExchangeDhReplyMessage>(message));
        }

        internal void OnKeyExchangeEcdhReplyMessageReceived(KeyExchangeEcdhReplyMessage message)
        {
            KeyExchangeEcdhReplyMessageReceived?.Invoke(this, new MessageEventArgs<KeyExchangeEcdhReplyMessage>(message));
        }

        internal void OnKeyExchangeHybridReplyMessageReceived(KeyExchangeHybridReplyMessage message)
        {
            KeyExchangeHybridReplyMessageReceived?.Invoke(this, new MessageEventArgs<KeyExchangeHybridReplyMessage>(message));
        }





        internal void OnNewKeysReceived(NewKeysMessage message)
        {

            SessionId ??= _keyExchange.ExchangeHash;


            if (_serverCipher is IDisposable disposableServerCipher)
            {
                disposableServerCipher.Dispose();
            }

            if (_clientCipher is IDisposable disposableClientCipher)
            {
                disposableClientCipher.Dispose();
            }

            _serverMac?.Dispose();
            _serverMac = null;

            _clientMac?.Dispose();
            _clientMac = null;


            _serverCipher = _keyExchange.CreateServerCipher(out _serverAead);
            _clientCipher = _keyExchange.CreateClientCipher(out _clientAead);

            _serverMac = _keyExchange.CreateServerHash(out _serverEtm);
            _clientMac = _keyExchange.CreateClientHash(out _clientEtm);

            _clientCompression = _keyExchange.CreateCompressor();
            _serverDecompression = _keyExchange.CreateDecompressor();

#if DEBUG
            if (SshNetLoggingConfiguration.WiresharkKeyLogFilePath is string path
                && _keyExchange is KeyExchange kex)
            {
                System.IO.File.AppendAllText(
                    path,
                    $"{Convert.ToHexString(ClientInitMessage.Cookie)} SHARED_SECRET {Convert.ToHexString(kex.SharedKey)}{Environment.NewLine}");
            }
#endif


            _keyExchange.HostKeyReceived -= KeyExchange_HostKeyReceived;
            _keyExchange.Dispose();
            _keyExchange = null;


            _sshMessageFactory.EnableActivatedMessages();

            if (_isInitialKex)
            {
                _isInitialKex = false;
                ClientInitMessage = BuildClientInitMessage(includeStrictKexPseudoAlgorithm: false);
            }

            if (_isStrictKex)
            {
                InboundPacketSequence = 0;
            }

            NewKeysReceived?.Invoke(this, new MessageEventArgs<NewKeysMessage>(message));


            _keyExchangeCompletedWaitHandle.Set();
        }




        void ISession.OnDisconnecting()
        {
            _isDisconnecting = true;
        }





        internal void OnUserAuthenticationRequestReceived(RequestMessage message)
        {
            UserAuthenticationRequestReceived?.Invoke(this, new MessageEventArgs<RequestMessage>(message));
        }





        internal void OnUserAuthenticationFailureReceived(FailureMessage message)
        {
            UserAuthenticationFailureReceived?.Invoke(this, new MessageEventArgs<FailureMessage>(message));
        }





        internal void OnUserAuthenticationSuccessReceived(SuccessMessage message)
        {
            UserAuthenticationSuccessReceived?.Invoke(this, new MessageEventArgs<SuccessMessage>(message));
        }





        internal void OnUserAuthenticationBannerReceived(BannerMessage message)
        {
            UserAuthenticationBannerReceived?.Invoke(this, new MessageEventArgs<BannerMessage>(message));
        }





        internal void OnUserAuthenticationInformationRequestReceived(InformationRequestMessage message)
        {
            UserAuthenticationInformationRequestReceived?.Invoke(this, new MessageEventArgs<InformationRequestMessage>(message));
        }

        internal void OnUserAuthenticationPasswordChangeRequiredReceived(PasswordChangeRequiredMessage message)
        {
            UserAuthenticationPasswordChangeRequiredReceived?.Invoke(this, new MessageEventArgs<PasswordChangeRequiredMessage>(message));
        }

        internal void OnUserAuthenticationPublicKeyReceived(PublicKeyMessage message)
        {
            UserAuthenticationPublicKeyReceived?.Invoke(this, new MessageEventArgs<PublicKeyMessage>(message));
        }





        internal void OnGlobalRequestReceived(GlobalRequestMessage message)
        {
            if (message.WantReply)
            {
                SendMessage(new RequestFailureMessage());
            }
        }





        internal void OnRequestSuccessReceived(RequestSuccessMessage message)
        {
            RequestSuccessReceived?.Invoke(this, new MessageEventArgs<RequestSuccessMessage>(message));
        }





        internal void OnRequestFailureReceived(RequestFailureMessage message)
        {
            RequestFailureReceived?.Invoke(this, new MessageEventArgs<RequestFailureMessage>(message));
        }





        internal void OnChannelOpenReceived(ChannelOpenMessage message)
        {
            ChannelOpenReceived?.Invoke(this, new MessageEventArgs<ChannelOpenMessage>(message));
        }





        internal void OnChannelOpenConfirmationReceived(ChannelOpenConfirmationMessage message)
        {
            ChannelOpenConfirmationReceived?.Invoke(this, new MessageEventArgs<ChannelOpenConfirmationMessage>(message));
        }





        internal void OnChannelOpenFailureReceived(ChannelOpenFailureMessage message)
        {
            ChannelOpenFailureReceived?.Invoke(this, new MessageEventArgs<ChannelOpenFailureMessage>(message));
        }





        internal void OnChannelWindowAdjustReceived(ChannelWindowAdjustMessage message)
        {
            ChannelWindowAdjustReceived?.Invoke(this, new MessageEventArgs<ChannelWindowAdjustMessage>(message));
        }





        internal void OnChannelDataReceived(ChannelDataMessage message)
        {
            ChannelDataReceived?.Invoke(this, new MessageEventArgs<ChannelDataMessage>(message));
        }





        internal void OnChannelExtendedDataReceived(ChannelExtendedDataMessage message)
        {
            ChannelExtendedDataReceived?.Invoke(this, new MessageEventArgs<ChannelExtendedDataMessage>(message));
        }





        internal void OnChannelEofReceived(ChannelEofMessage message)
        {
            ChannelEofReceived?.Invoke(this, new MessageEventArgs<ChannelEofMessage>(message));
        }





        internal void OnChannelCloseReceived(ChannelCloseMessage message)
        {
            ChannelCloseReceived?.Invoke(this, new MessageEventArgs<ChannelCloseMessage>(message));
        }





        internal void OnChannelRequestReceived(ChannelRequestMessage message)
        {
            ChannelRequestReceived?.Invoke(this, new MessageEventArgs<ChannelRequestMessage>(message));
        }





        internal void OnChannelSuccessReceived(ChannelSuccessMessage message)
        {
            ChannelSuccessReceived?.Invoke(this, new MessageEventArgs<ChannelSuccessMessage>(message));
        }





        internal void OnChannelFailureReceived(ChannelFailureMessage message)
        {
            ChannelFailureReceived?.Invoke(this, new MessageEventArgs<ChannelFailureMessage>(message));
        }

        private void KeyExchange_HostKeyReceived(object sender, HostKeyEventArgs e)
        {
            HostKeyReceived?.Invoke(this, e);
        }





        public void RegisterMessage(string messageName)
        {
            _sshMessageFactory.EnableAndActivateMessage(messageName);
        }





        public void UnRegisterMessage(string messageName)
        {
            _sshMessageFactory.DisableAndDeactivateMessage(messageName);
        }











        private Message LoadMessage(byte[] data, int offset, int count)
        {
            var messageType = data[offset];

            var message = _sshMessageFactory.Create(messageType);
            message.Load(data, offset + 1, count - 1);

            if (_logger.IsEnabled(LogLevel.Trace))
            {
                _logger.LogTrace("[{SessionId}] Received message {MessageName}({MessageNumber}) from server: '{Message}'.", SessionIdHex, message.MessageName, message.MessageNumber, message.ToString());
            }

            return message;
        }













        private static int TrySocketRead(Socket socket, byte[] buffer, int offset, int length, int minimumLength)
        {
            Debug.Assert(offset >= 0);
            Debug.Assert((uint)length <= buffer.Length - offset);
            Debug.Assert(minimumLength <= length);

            if (socket is null)
            {
                return 0;
            }

            var totalRead = 0;
            while (totalRead < minimumLength)
            {
                var read = socket.Receive(buffer, offset + totalRead, length - totalRead, SocketFlags.None);

                if (read == 0)
                {
                    return totalRead;
                }

                totalRead += read;
            }

            return totalRead;
        }




        private void SocketDisconnectAndDispose()
        {
            lock (_socketDisposeLock)
            {
                if (_socket is null)
                {
                    return;
                }

                if (_socket.Connected)
                {
                    try
                    {
                        _logger.LogDebug("[{SessionId}] Shutting down socket.", SessionIdHex);







                        _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch (SocketException ex)
                    {
                        _logger.LogInformation(ex, "Failure shutting down socket");
                    }
                }

                _logger.LogDebug("[{SessionId}] Disposing socket.", SessionIdHex);
                _socket.Dispose();
                _logger.LogDebug("[{SessionId}] Disposed socket.", SessionIdHex);
                _socket = null;
            }
        }




        private void MessageListener()
        {
            try
            {
                if (_socket is { } s)
                {
                    s.ReceiveTimeout = 0;
                }


                while (true)
                {
                    var message = ReceiveMessage(_socket);
                    if (message is null)
                    {

                        break;
                    }


                    message.Process(this);
                }


                RaiseError(CreateConnectionAbortedByServerException());
            }
            catch (SocketException ex)
            {
                RaiseError(new SshConnectionException(ex.Message, DisconnectReason.ConnectionLost, ex));
            }
            catch (Exception exp)
            {
                RaiseError(exp);
            }
            finally
            {

                _ = _messageListenerCompleted.Set();
            }
        }





        private void RaiseError(Exception exp)
        {
            _logger.LogInformation(exp, "[{SessionId}] Raised exception", SessionIdHex);

            if (_isDisconnecting && exp is SshConnectionException or ObjectDisposedException)
            {

                return;
            }


            _exception = exp;
            _ = _exceptionWaitHandle.Set();

            ErrorOccured?.Invoke(this, new ExceptionEventArgs(exp));

            if (exp is SshConnectionException connectionException)
            {
                _logger.LogInformation(exp, "[{SessionId}] Disconnecting after exception", SessionIdHex);
                Disconnect(connectionException.DisconnectReason, exp.Message);
            }
        }





        private void Reset()
        {
            _ = _exceptionWaitHandle?.Reset();
            _keyExchangeCompletedWaitHandle?.Reset();
            _ = _messageListenerCompleted?.Set();

            SessionId = null;
            _isDisconnectMessageSent = false;
            _isDisconnecting = false;
            _isAuthenticated = false;
            _exception = null;
        }

        private static SshConnectionException CreateConnectionAbortedByServerException()
        {
            return new SshConnectionException("An established connection was aborted by the server.",
            DisconnectReason.ConnectionLost);
        }

        private KeyExchangeInitMessage BuildClientInitMessage(bool includeStrictKexPseudoAlgorithm)
        {
            return new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = includeStrictKexPseudoAlgorithm ?
                                        ConnectionInfo.KeyExchangeAlgorithms.Keys.Concat(["kex-strict-c-v00@openssh.com"]).ToArray() :
                                        ConnectionInfo.KeyExchangeAlgorithms.Keys.ToArray(),
                ServerHostKeyAlgorithms = ConnectionInfo.HostKeyAlgorithms.Keys.ToArray(),
                EncryptionAlgorithmsClientToServer = ConnectionInfo.Encryptions.Keys.ToArray(),
                EncryptionAlgorithmsServerToClient = ConnectionInfo.Encryptions.Keys.ToArray(),
                MacAlgorithmsClientToServer = ConnectionInfo.HmacAlgorithms.Keys.ToArray(),
                MacAlgorithmsServerToClient = ConnectionInfo.HmacAlgorithms.Keys.ToArray(),
                CompressionAlgorithmsClientToServer = ConnectionInfo.CompressionAlgorithms.Keys.ToArray(),
                CompressionAlgorithmsServerToClient = ConnectionInfo.CompressionAlgorithms.Keys.ToArray(),
                LanguagesClientToServer = new[] { string.Empty },
                LanguagesServerToClient = new[] { string.Empty },
                FirstKexPacketFollows = false,
                Reserved = 0,
            };
        }

        private bool _disposed;




        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }





        private void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                _logger.LogDebug("[{SessionId}] Disposing session.", SessionIdHex);

                Disconnect();

                var serviceAccepted = _serviceAccepted;
                if (serviceAccepted != null)
                {
                    serviceAccepted.Dispose();
                    _serviceAccepted = null;
                }

                var exceptionWaitHandle = _exceptionWaitHandle;
                if (exceptionWaitHandle != null)
                {
                    exceptionWaitHandle.Dispose();
                    _exceptionWaitHandle = null;
                }

                var keyExchangeCompletedWaitHandle = _keyExchangeCompletedWaitHandle;
                if (keyExchangeCompletedWaitHandle != null)
                {
                    keyExchangeCompletedWaitHandle.Dispose();
                    _keyExchangeCompletedWaitHandle = null;
                }

                if (_serverCipher is IDisposable disposableServerCipher)
                {
                    disposableServerCipher.Dispose();
                }

                if (_clientCipher is IDisposable disposableClientCipher)
                {
                    disposableClientCipher.Dispose();
                }

                var serverMac = _serverMac;
                if (serverMac != null)
                {
                    serverMac.Dispose();
                    _serverMac = null;
                }

                var clientMac = _clientMac;
                if (clientMac != null)
                {
                    clientMac.Dispose();
                    _clientMac = null;
                }

                var serverDecompression = _serverDecompression;
                if (serverDecompression != null)
                {
                    serverDecompression.Dispose();
                    _serverDecompression = null;
                }

                var clientCompression = _clientCompression;
                if (clientCompression != null)
                {
                    clientCompression.Dispose();
                    _clientCompression = null;
                }

                var keyExchange = _keyExchange;
                if (keyExchange != null)
                {
                    keyExchange.HostKeyReceived -= KeyExchange_HostKeyReceived;
                    keyExchange.Dispose();
                    _keyExchange = null;
                }

                var messageListenerCompleted = _messageListenerCompleted;
                if (messageListenerCompleted != null)
                {
                    messageListenerCompleted.Dispose();
                    _messageListenerCompleted = null;
                }

                _disposed = true;
            }
        }





        IConnectionInfo ISession.ConnectionInfo
        {
            get { return ConnectionInfo; }
        }








        WaitHandle ISession.MessageListenerCompleted
        {
            get { return _messageListenerCompleted; }
        }







        IChannelSession ISession.CreateChannelSession()
        {
            return new ChannelSession(this, NextChannelNumber, InitialLocalWindowSize, LocalChannelDataPacketSize);
        }







        IChannelDirectTcpip ISession.CreateChannelDirectTcpip()
        {
            return new ChannelDirectTcpip(this, NextChannelNumber, InitialLocalWindowSize, LocalChannelDataPacketSize);
        }










        IChannelForwardedTcpip ISession.CreateChannelForwardedTcpip(uint remoteChannelNumber,
                                                                    uint remoteWindowSize,
                                                                    uint remoteChannelDataPacketSize)
        {
            return new ChannelForwardedTcpip(this,
                                             NextChannelNumber,
                                             InitialLocalWindowSize,
                                             LocalChannelDataPacketSize,
                                             remoteChannelNumber,
                                             remoteWindowSize,
                                             remoteChannelDataPacketSize);
        }








        void ISession.SendMessage(Message message)
        {
            SendMessage(message);
        }













        bool ISession.TrySendMessage(Message message)
        {
            return TrySendMessage(message);
        }
    }




    internal enum WaitResult
    {



        Success = 1,




        TimedOut = 2,




        Disconnected = 3,




        Failed = 4
    }
}
