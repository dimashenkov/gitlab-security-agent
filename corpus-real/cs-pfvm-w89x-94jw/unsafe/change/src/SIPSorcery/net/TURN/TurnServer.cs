
















using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{



    public class TurnServerConfig
    {



        public IPAddress ListenAddress { get; set; } = IPAddress.Loopback;




        public int Port { get; set; } = 3478;




        public bool EnableTcp { get; set; } = true;




        public bool EnableUdp { get; set; } = true;





        public IPAddress RelayAddress { get; set; }




        public string Username { get; set; } = "turn-user";




        public string Password { get; set; } = "turn-pass";




        public string Realm { get; set; } = "sipsorcery";




        public int DefaultLifetimeSeconds { get; set; } = 600;









        public string StaticAuthSecret { get; set; }






        public int RelayPortMin { get; set; } = 0;




        public int RelayPortMax { get; set; } = 0;
    }




    public class TurnAllocation : IDisposable
    {

        public string Id { get; set; } = string.Empty;


        public UdpClient RelaySocket { get; set; }


        public IPEndPoint RelayEndPoint { get; set; }


        public DateTime Expiry { get; set; }





        public ConcurrentDictionary<string, DateTime> Permissions { get; } = new ConcurrentDictionary<string, DateTime>();


        public ConcurrentDictionary<ushort, IPEndPoint> ChannelBindings { get; } = new ConcurrentDictionary<ushort, IPEndPoint>();


        public ConcurrentDictionary<string, ushort> ReverseChannelBindings { get; } = new ConcurrentDictionary<string, ushort>();


        internal NetworkStream TcpStream { get; set; }


        internal IPEndPoint UdpClientEndPoint { get; set; }


        internal UdpClient UdpControlSocket { get; set; }


        internal CancellationTokenSource Cts { get; set; } = new CancellationTokenSource();




        internal byte[] HmacKey { get; set; }

        public void Dispose()
        {
            try { Cts.Cancel(); } catch { }
            try { Cts.Dispose(); } catch { }
            try { RelaySocket?.Dispose(); } catch { }
        }
    }





























































    [Experimental("SIPSORCERY001", UrlFormat = "https://github.com/sipsorcery-org/sipsorcery/blob/master/docs/diagnostics/{0}.md")]
    public class TurnServer : IDisposable
    {
        private const int PERMISSION_LIFETIME_SECONDS = 300;
        private const int CLEANUP_INTERVAL_SECONDS = 30;

        private static readonly ILogger logger = LogFactory.CreateLogger<TurnServer>();

        private readonly TurnServerConfig _config;
        private readonly byte[] _hmacKey;
        private readonly IPAddress _relayAddress;
        private readonly bool _useStaticAuthSecret;
        private readonly byte[] _realmBytes;
        private readonly byte[] _staticAuthSecretBytes;
        private int _nextRelayPortOffset = -1;

        private TcpListener _tcpListener;
        private UdpClient _udpSocket;
        private Timer _cleanupTimer;
        private volatile bool _running;

        private readonly ConcurrentDictionary<string, TurnAllocation> _allocations =
            new ConcurrentDictionary<string, TurnAllocation>();




        private HashSet<IPAddress> _localIPv4Cache;
        private DateTime _localIPv4CacheExpiry = DateTime.MinValue;




        public IReadOnlyDictionary<string, TurnAllocation> Allocations => _allocations;













        public IPEndPoint TranslateLocalSource(IPEndPoint observedSource)
        {
            if (observedSource == null)
            {
                return null;
            }


            var addr = observedSource.Address.IsIPv4MappedToIPv6
                ? observedSource.Address.MapToIPv4()
                : observedSource.Address;

            if (!IsLocalIPv4(addr))
            {
                return null;
            }




            foreach (var alloc in _allocations.Values)
            {
                if (alloc.RelayEndPoint?.Port == observedSource.Port)
                {
                    return new IPEndPoint(_relayAddress, observedSource.Port);
                }
            }

            return null;
        }

        private bool IsLocalIPv4(IPAddress address)
        {
            if (IPAddress.IsLoopback(address))
            {
                return true;
            }


            if (_localIPv4Cache == null || DateTime.UtcNow > _localIPv4CacheExpiry)
            {
                try
                {
                    _localIPv4Cache = new HashSet<IPAddress>(
                        NetworkInterface.GetAllNetworkInterfaces()
                            .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                            .Where(uni => uni.Address.AddressFamily == AddressFamily.InterNetwork)
                            .Select(uni => uni.Address));
                }
                catch
                {
                    _localIPv4Cache = new HashSet<IPAddress>();
                }
                _localIPv4CacheExpiry = DateTime.UtcNow.AddSeconds(60);
            }

            return _localIPv4Cache.Contains(address);
        }





        public TurnServer(TurnServerConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _relayAddress = config.RelayAddress ?? config.ListenAddress;
            _useStaticAuthSecret = !string.IsNullOrEmpty(_config.StaticAuthSecret);
            _realmBytes = Encoding.UTF8.GetBytes(_config.Realm);

            if (_useStaticAuthSecret)
            {
                _staticAuthSecretBytes = Encoding.UTF8.GetBytes(_config.StaticAuthSecret);
            }
            else
            {

                _hmacKey = DeriveLongTermKey(_config.Username, _config.Realm, _config.Password);
            }


        }

        private static byte[] DeriveLongTermKey(string username, string realm, string password)
        {
            var input = Encoding.UTF8.GetBytes($"{username}:{realm}:{password}");
#if NET5_0_OR_GREATER
            return MD5.HashData(input);
#else
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(input);
            }
#endif
        }




        public void Start()
        {
            if (_running)
            {
                return;
            }

            _running = true;

            if (_config.EnableTcp)
            {
                _tcpListener = new TcpListener(_config.ListenAddress, _config.Port);
                _tcpListener.Start();
                _ = AcceptTcpClientsAsync();
                logger.LogDebug("TURN server TCP listener started on {Address}:{Port}.",
                    _config.ListenAddress, _config.Port);
            }

            if (_config.EnableUdp)
            {
                _udpSocket = new UdpClient(new IPEndPoint(_config.ListenAddress, _config.Port));
                _ = ReceiveUdpAsync();
                logger.LogDebug("TURN server UDP listener started on {Address}:{Port}.",
                    _config.ListenAddress, _config.Port);
            }

            _cleanupTimer = new Timer(CleanExpiredAllocations, null,
                TimeSpan.FromSeconds(CLEANUP_INTERVAL_SECONDS),
                TimeSpan.FromSeconds(CLEANUP_INTERVAL_SECONDS));

            logger.LogInformation("TURN server started on {Address}:{Port} (TCP={Tcp}, UDP={Udp}).",
                _config.ListenAddress, _config.Port, _config.EnableTcp, _config.EnableUdp);



            logger.LogWarning("TURN server is intended for development, testing and small scale or embedded " +
                "scenarios and is not hardened for production use. It has no nonce validation, no rate limiting " +
                "or per-IP allocation caps and no TLS/DTLS on the control channel. Use coturn or an equivalent " +
                "for production deployments.");
        }




        public void Stop()
        {
            if (!_running)
            {
                return;
            }

            _running = false;

            _cleanupTimer?.Dispose();
            _cleanupTimer = null;

            try { _tcpListener?.Stop(); } catch { }
            try { _udpSocket?.Dispose(); } catch { }

            foreach (var kvp in _allocations)
            {
                kvp.Value.Dispose();
            }
            _allocations.Clear();

            logger.LogInformation("TURN server stopped.");
        }

        public void Dispose()
        {
            Stop();
        }

        #region TCP handling

        private async Task AcceptTcpClientsAsync()
        {
            try
            {
                while (_running)
                {
                    TcpClient client;
                    try
                    {
                        client = await _tcpListener.AcceptTcpClientAsync().ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException) { break; }
                    catch (SocketException) { break; }

                    logger.LogDebug("TURN TCP client connected from {Remote}.", client.Client.RemoteEndPoint);
                    _ = HandleTcpClientAsync(client);
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                logger.LogError(ex, "TURN TCP accept loop error. {ErrorMessage}", ex.Message);
            }
        }

        private async Task HandleTcpClientAsync(TcpClient tcpClient)
        {
            var clientEndPoint = tcpClient.Client.RemoteEndPoint as IPEndPoint;
            var clientId = clientEndPoint?.ToString() ?? "unknown";
            var stream = tcpClient.GetStream();
            var header = new byte[4];
            var paddingBuffer = new byte[3];
            TurnAllocation allocation = null;

            try
            {
                while (_running && tcpClient.Connected)
                {

                    if (!await ReadExactAsync(stream, header, 0, 4).ConfigureAwait(false))
                        break;

                    if ((header[0] & 0xC0) == 0x40)
                    {

                        var channelNumber = (ushort)((header[0] << 8) | header[1]);
                        var dataLength = (ushort)((header[2] << 8) | header[3]);

                        var data = new byte[dataLength];
                        if (dataLength > 0 && !await ReadExactAsync(stream, data, 0, dataLength).ConfigureAwait(false))
                            break;


                        var padding = (4 - (dataLength % 4)) % 4;
                        if (padding > 0)
                        {
                            if (!await ReadExactAsync(stream, paddingBuffer, 0, padding).ConfigureAwait(false))
                                break;
                        }

                        HandleChannelData(allocation, channelNumber, data, 0, data.Length);
                    }
                    else
                    {

                        var msgLength = (ushort)((header[2] << 8) | header[3]);
                        var remaining = 16 + msgLength;
                        var fullMsg = new byte[4 + remaining];
                        Buffer.BlockCopy(header, 0, fullMsg, 0, 4);

                        if (remaining > 0 && !await ReadExactAsync(stream, fullMsg, 4, remaining).ConfigureAwait(false))
                            break;

                        var stunMsg = STUNMessage.ParseSTUNMessage(fullMsg, fullMsg.Length);
                        if (stunMsg == null)
                        {
                            logger.LogWarning("Failed to parse STUN message from TCP client {Client}.", clientId);
                            continue;
                        }

                        ProcessMessage(stunMsg, clientId, clientEndPoint,
                            (responseBytes) => SendTcpResponseAsync(stream, responseBytes),
                            ref allocation,
                            stream, null, null);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (System.IO.IOException) { }
            catch (Exception ex)
            {
                logger.LogError(ex, "TURN TCP client handler error for {Client}. {ErrorMessage}", clientId, ex.Message);
            }
            finally
            {
                if (allocation != null)
                {
                    _allocations.TryRemove(allocation.Id, out _);
                    allocation.Dispose();
                    logger.LogDebug("Cleaned up TCP allocation for {Client}.", clientId);
                }
                tcpClient.Dispose();
            }
        }

        private static async Task SendTcpResponseAsync(NetworkStream stream, byte[] data)
        {
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count)
        {
            var totalRead = 0;
            while (totalRead < count)
            {
                var read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead).ConfigureAwait(false);
                if (read == 0) return false;
                totalRead += read;
            }
            return true;
        }

        #endregion

        #region UDP handling

        private async Task ReceiveUdpAsync()
        {
            try
            {
                while (_running)
                {
                    UdpReceiveResult result;
                    try
                    {
                        result = await _udpSocket.ReceiveAsync().ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException) { break; }
                    catch (SocketException) { break; }

                    HandleUdpDatagram(result.Buffer, result.RemoteEndPoint);
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                logger.LogError(ex, "TURN UDP receive loop error. {ErrorMessage}", ex.Message);
            }
        }

        private void HandleUdpDatagram(byte[] data, IPEndPoint remoteEndPoint)
        {
            var clientId = remoteEndPoint.ToString();

            if (data.Length >= 4 && (data[0] & 0xC0) == 0x40)
            {

                var channelNumber = (ushort)((data[0] << 8) | data[1]);
                var dataLength = (ushort)((data[2] << 8) | data[3]);

                if (data.Length >= 4 + dataLength)
                {

                    if (_allocations.TryGetValue(clientId, out var allocation))
                    {
                        HandleChannelData(allocation, channelNumber, data, 4, dataLength);
                    }
                }
                return;
            }

            var stunMsg = STUNMessage.ParseSTUNMessage(data, data.Length);
            if (stunMsg == null)
            {
                logger.LogWarning("Failed to parse STUN message from UDP client {Client}.", clientId);
                return;
            }

            _allocations.TryGetValue(clientId, out var udpAllocation);

            ProcessMessage(stunMsg, clientId, remoteEndPoint,
                (responseBytes) => SendUdpResponseAsync(remoteEndPoint, responseBytes),
                ref udpAllocation,
                null, remoteEndPoint, _udpSocket);
        }

        private async Task SendUdpResponseAsync(IPEndPoint remoteEndPoint, byte[] data)
        {
            try
            {
                await _udpSocket.SendAsync(data, data.Length, remoteEndPoint).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Failed to send UDP response to {Endpoint}. {ErrorMessage}", remoteEndPoint, ex.Message);
            }
        }

        #endregion

        #region Message processing

        private void ProcessMessage(
            STUNMessage msg,
            string clientId,
            IPEndPoint clientEndPoint,
            Func<byte[], Task> sendResponse,
            ref TurnAllocation allocation,
            NetworkStream tcpStream,
            IPEndPoint udpClientEndPoint,
            UdpClient udpControlSocket)
        {
            var msgType = msg.Header.MessageType;
            logger.LogDebug("TURN {Type} from {Client}.", msgType, clientId);

            switch (msgType)
            {
                case STUNMessageTypesEnum.BindingRequest:
                    {
                        var response = HandleBindingRequest(msg, clientEndPoint);
                        var bytes = response.ToByteBuffer(null, false);
                        _ = sendResponse(bytes);
                    }
                    break;

                case STUNMessageTypesEnum.Allocate:
                    {
                        var (response, signingKey) = HandleAllocate(msg, clientId, clientEndPoint,
                            tcpStream, udpClientEndPoint, udpControlSocket,
                            ref allocation);
                        var bytes = signingKey != null
                            ? response.ToByteBuffer(signingKey, true)
                            : response.ToByteBuffer(null, false);
                        _ = sendResponse(bytes);
                    }
                    break;

                case STUNMessageTypesEnum.Refresh:
                    {
                        var response = HandleRefresh(msg, clientId, ref allocation);
                        var bytes = SignResponse(response, allocation);
                        _ = sendResponse(bytes);
                    }
                    break;

                case STUNMessageTypesEnum.CreatePermission:
                    {
                        var response = HandleCreatePermission(msg, allocation);
                        var bytes = SignResponse(response, allocation);
                        _ = sendResponse(bytes);
                    }
                    break;

                case STUNMessageTypesEnum.ChannelBind:
                    {
                        var response = HandleChannelBind(msg, allocation);
                        var bytes = SignResponse(response, allocation);
                        _ = sendResponse(bytes);
                    }
                    break;

                case STUNMessageTypesEnum.SendIndication:
                    HandleSendIndication(msg, allocation);
                    break;

                default:
                    logger.LogWarning("Unhandled STUN message type: {Type}.", msgType);
                    break;
            }
        }

        private STUNMessage HandleBindingRequest(STUNMessage request, IPEndPoint clientEndPoint)
        {
            var response = new STUNMessage(STUNMessageTypesEnum.BindingSuccessResponse);
            response.Header.TransactionId = request.Header.TransactionId;


            if (clientEndPoint != null)
            {
                response.AddXORMappedAddressAttribute(clientEndPoint.Address, clientEndPoint.Port);
            }
            return response;
        }







        private byte[] SignResponse(STUNMessage response, TurnAllocation allocation)
        {
            var key = allocation?.HmacKey ?? _hmacKey;
            return key != null
                ? response.ToByteBuffer(key, true)
                : response.ToByteBuffer(null, false);
        }






        private bool TryDeriveRestKey(STUNMessage request, out byte[] key, out string rejectReason)
        {
            key = null;
            rejectReason = null;

            var usernameAttr = request.GetFirstAttribute(STUNAttributeTypesEnum.Username);
            if (usernameAttr?.Value == null || usernameAttr.Value.Length == 0)
            {
                rejectReason = "missing USERNAME";
                return false;
            }

            var username = Encoding.UTF8.GetString(usernameAttr.Value);
            var colonIdx = username.IndexOf(':');
            if (colonIdx <= 0)
            {
                rejectReason = "USERNAME not in '<expiry>:<user>' form";
                return false;
            }

            if (!long.TryParse(username.Substring(0, colonIdx), out var expiryUnix))
            {
                rejectReason = "USERNAME expiry is not a unix timestamp";
                return false;
            }

            var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (expiryUnix <= nowUnix)
            {
                rejectReason = "credential expired";
                return false;
            }


            var msgBytes = Encoding.UTF8.GetBytes($"{username}:{_config.Realm}");
            string password;
#if NET6_0_OR_GREATER
            password = Convert.ToBase64String(HMACSHA1.HashData(_staticAuthSecretBytes, msgBytes));
#else
            using (var hmac = new HMACSHA1(_staticAuthSecretBytes))
            {
                password = Convert.ToBase64String(hmac.ComputeHash(msgBytes));
            }
#endif

            key = DeriveLongTermKey(username, _config.Realm, password);
            return true;
        }

        private (STUNMessage response, byte[] signingKey) HandleAllocate(
            STUNMessage request,
            string clientId,
            IPEndPoint clientEndPoint,
            NetworkStream tcpStream,
            IPEndPoint udpClientEndPoint,
            UdpClient udpControlSocket,
            ref TurnAllocation allocation)
        {

            var hasIntegrity = HasAttribute(request, STUNAttributeTypesEnum.MessageIntegrity);

            if (!hasIntegrity)
            {

                return (BuildAuthChallenge(request), null);
            }




            byte[] requestKey;
            if (_useStaticAuthSecret)
            {
                if (!TryDeriveRestKey(request, out requestKey, out var reason))
                {
                    logger.LogWarning("TURN Allocate: REST credential rejected from {Client}: {Reason}.",
                        clientId, reason);
                    return (BuildAuthChallenge(request), null);
                }
            }
            else
            {
                requestKey = _hmacKey;
            }

            if (!request.CheckIntegrity(requestKey))
            {
                logger.LogWarning("TURN Allocate: integrity check failed from {Client}.", clientId);
                var errResponse = new STUNMessage(STUNMessageTypesEnum.AllocateErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(401, "Unauthorized"));
                return (errResponse, null);
            }


            if (allocation != null)
            {
                var errResponse = new STUNMessage(STUNMessageTypesEnum.AllocateErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(437, "Allocation Mismatch"));
                return (errResponse, requestKey);
            }


            if (!TryBindRelaySocket(out var relaySocket))
            {
                logger.LogWarning("TURN Allocate: no free relay port in [{Min}..{Max}] for {Client}.",
                    _config.RelayPortMin, _config.RelayPortMax, clientId);
                var errResponse = new STUNMessage(STUNMessageTypesEnum.AllocateErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(508, "Insufficient Capacity"));
                return (errResponse, requestKey);
            }
            var relayEndpoint = (IPEndPoint)relaySocket.Client.LocalEndPoint;

            allocation = new TurnAllocation
            {
                Id = clientId,
                RelaySocket = relaySocket,
                RelayEndPoint = relayEndpoint,
                Expiry = DateTime.UtcNow.AddSeconds(_config.DefaultLifetimeSeconds),
                TcpStream = tcpStream,
                UdpClientEndPoint = udpClientEndPoint,
                UdpControlSocket = udpControlSocket,
                HmacKey = requestKey,
            };

            _allocations[clientId] = allocation;


            _ = RelayUdpToClientAsync(allocation);

            logger.LogInformation("TURN allocation created for {Client}: relay port {Port}.",
                clientId, relayEndpoint.Port);


            var response = new STUNMessage(STUNMessageTypesEnum.AllocateSuccessResponse);
            response.Header.TransactionId = request.Header.TransactionId;


            response.Attributes.Add(new STUNXORAddressAttribute(
                STUNAttributeTypesEnum.XORRelayedAddress,
                relayEndpoint.Port,
                _relayAddress,
                request.Header.TransactionId));




            if (clientEndPoint != null)
            {
                response.Attributes.Add(new STUNXORAddressAttribute(
                    STUNAttributeTypesEnum.XORMappedAddress,
                    clientEndPoint.Port,
                    clientEndPoint.Address,
                    request.Header.TransactionId));
            }


            response.Attributes.Add(new STUNAttribute(
                STUNAttributeTypesEnum.Lifetime, (uint)_config.DefaultLifetimeSeconds));

            return (response, requestKey);
        }

        private STUNMessage BuildAuthChallenge(STUNMessage request)
        {
            var errResponse = new STUNMessage(STUNMessageTypesEnum.AllocateErrorResponse);
            errResponse.Header.TransactionId = request.Header.TransactionId;
            errResponse.Attributes.Add(new STUNErrorCodeAttribute(401, "Unauthorized"));
            errResponse.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Realm,
                _realmBytes));
            errResponse.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Nonce,
                Encoding.UTF8.GetBytes(GenerateNonce())));
            return errResponse;
        }






        private bool TryBindRelaySocket(out UdpClient socket)
        {
            socket = null;
            if (_config.RelayPortMin <= 0 || _config.RelayPortMax < _config.RelayPortMin)
            {
                socket = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                return true;
            }

            var portCount = _config.RelayPortMax - _config.RelayPortMin + 1;
            var startOffset = (uint)Interlocked.Increment(ref _nextRelayPortOffset);

            for (int i = 0; i < portCount; i++)
            {
                var port = _config.RelayPortMin + (int)((startOffset + (uint)i) % (uint)portCount);
                try
                {
                    socket = new UdpClient(new IPEndPoint(IPAddress.Any, port));
                    return true;
                }
                catch (SocketException)
                {

                }
            }
            return false;
        }

        private STUNMessage HandleRefresh(STUNMessage request, string clientId, ref TurnAllocation allocation)
        {
            if (allocation == null)
            {
                var errResponse = new STUNMessage(STUNMessageTypesEnum.RefreshErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(437, "Allocation Mismatch"));
                return errResponse;
            }


            var lifetimeAttr = request.GetFirstAttribute(STUNAttributeTypesEnum.Lifetime);
            uint lifetime = (uint)_config.DefaultLifetimeSeconds;
            if (lifetimeAttr?.Value != null && lifetimeAttr.Value.Length >= 4)
            {
                lifetime = (uint)((lifetimeAttr.Value[0] << 24) | (lifetimeAttr.Value[1] << 16) |
                                  (lifetimeAttr.Value[2] << 8) | lifetimeAttr.Value[3]);
            }

            if (lifetime == 0)
            {
                _allocations.TryRemove(allocation.Id, out _);
                allocation.Dispose();
                allocation = null;
                logger.LogInformation("TURN allocation deleted by refresh (lifetime=0) for {Client}.", clientId);
            }
            else
            {
                allocation.Expiry = DateTime.UtcNow.AddSeconds(lifetime);
            }

            var response = new STUNMessage(STUNMessageTypesEnum.RefreshSuccessResponse);
            response.Header.TransactionId = request.Header.TransactionId;
            response.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Lifetime, lifetime));
            return response;
        }

        private STUNMessage HandleCreatePermission(STUNMessage request, TurnAllocation allocation)
        {
            if (allocation == null)
            {
                var errResponse = new STUNMessage(STUNMessageTypesEnum.CreatePermissionErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(437, "Allocation Mismatch"));
                return errResponse;
            }

            var permissionExpiry = DateTime.UtcNow.AddSeconds(PERMISSION_LIFETIME_SECONDS);
            foreach (var attr in request.Attributes)
            {
                if (attr.AttributeType != STUNAttributeTypesEnum.XORPeerAddress)
                {
                    continue;
                }

                var xorAddr = new STUNXORAddressAttribute(
                    STUNAttributeTypesEnum.XORPeerAddress,
                    attr.Value, request.Header.TransactionId);
                var peerIp = xorAddr.Address.ToString();
                allocation.Permissions[peerIp] = permissionExpiry;
                logger.LogDebug("TURN permission added: {Address} (expires in {Seconds}s).",
                    peerIp, PERMISSION_LIFETIME_SECONDS);
            }

            var response = new STUNMessage(STUNMessageTypesEnum.CreatePermissionSuccessResponse);
            response.Header.TransactionId = request.Header.TransactionId;
            return response;
        }

        private STUNMessage HandleChannelBind(STUNMessage request, TurnAllocation allocation)
        {
            if (allocation == null)
            {
                var errResponse = new STUNMessage(STUNMessageTypesEnum.ChannelBindErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(437, "Allocation Mismatch"));
                return errResponse;
            }

            var channelAttr = request.GetFirstAttribute(STUNAttributeTypesEnum.ChannelNumber);
            if (channelAttr?.Value == null || channelAttr.Value.Length < 2)
            {
                var errResponse = new STUNMessage(STUNMessageTypesEnum.ChannelBindErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(400, "Bad Request"));
                return errResponse;
            }

            var channelNumber = (ushort)((channelAttr.Value[0] << 8) | channelAttr.Value[1]);

            var peerAttr = request.GetFirstAttribute(STUNAttributeTypesEnum.XORPeerAddress);
            if (peerAttr?.Value == null)
            {
                var errResponse = new STUNMessage(STUNMessageTypesEnum.ChannelBindErrorResponse);
                errResponse.Header.TransactionId = request.Header.TransactionId;
                errResponse.Attributes.Add(new STUNErrorCodeAttribute(400, "Bad Request"));
                return errResponse;
            }

            var peerAddr = new STUNXORAddressAttribute(
                STUNAttributeTypesEnum.XORPeerAddress,
                peerAttr.Value, request.Header.TransactionId);
            var peerEndpoint = new IPEndPoint(peerAddr.Address, peerAddr.Port);

            allocation.ChannelBindings[channelNumber] = peerEndpoint;
            allocation.ReverseChannelBindings[peerEndpoint.ToString()] = channelNumber;

            logger.LogDebug("TURN channel bind: 0x{Channel:X4} -> {Peer}.", channelNumber, peerEndpoint);

            var response = new STUNMessage(STUNMessageTypesEnum.ChannelBindSuccessResponse);
            response.Header.TransactionId = request.Header.TransactionId;
            return response;
        }

        private void HandleSendIndication(STUNMessage msg, TurnAllocation allocation)
        {
            if (allocation == null) return;

            var peerAttr = msg.GetFirstAttribute(STUNAttributeTypesEnum.XORPeerAddress);
            var dataAttr = msg.GetFirstAttribute(STUNAttributeTypesEnum.Data);

            if (peerAttr?.Value == null || dataAttr?.Value == null) return;

            var peerAddr = new STUNXORAddressAttribute(
                STUNAttributeTypesEnum.XORPeerAddress,
                peerAttr.Value, msg.Header.TransactionId);
            var peerEndpoint = new IPEndPoint(peerAddr.Address, peerAddr.Port);


            if (!HasPermission(allocation, peerEndpoint.Address.ToString()))
            {
                logger.LogDebug("TURN SendIndication dropped: no permission for {Peer}.", peerEndpoint);
                return;
            }

            try
            {
                allocation.RelaySocket.Send(dataAttr.Value, dataAttr.Value.Length, peerEndpoint);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Failed to relay UDP to {Peer}. {ErrorMessage}", peerEndpoint, ex.Message);
            }
        }

        private void HandleChannelData(
            TurnAllocation allocation,
            ushort channelNumber,
            byte[] data,
            int offset,
            int length)
        {
            if (allocation == null) return;

            if (allocation.ChannelBindings.TryGetValue(channelNumber, out var peer))
            {
                try
                {
                    if (offset == 0 && length == data.Length)
                    {
                        allocation.RelaySocket.Send(data, length, peer);
                    }
                    else
                    {
                        allocation.RelaySocket.Client.SendTo(
                            data, offset, length, SocketFlags.None, peer);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Failed to relay channel data to {Peer}. {ErrorMessage}", peer, ex.Message);
                }
            }
        }

        #endregion

        #region Relay (peer → client)

        private async Task RelayUdpToClientAsync(TurnAllocation allocation)
        {
            try
            {
                while (!allocation.Cts.IsCancellationRequested)
                {
                    UdpReceiveResult result;
                    try
                    {
                        result = await allocation.RelaySocket.ReceiveAsync().ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException) { break; }
                    catch (SocketException) { break; }

                    var now = DateTime.UtcNow;
                    var senderIp = result.RemoteEndPoint.Address.ToString();
                    var senderKey = result.RemoteEndPoint.ToString();


                    if (!HasPermission(allocation, senderIp, now))
                    {
                        logger.LogDebug("TURN relay dropped packet from {Sender}: no permission.", senderKey);
                        continue;
                    }


                    if (allocation.ReverseChannelBindings.TryGetValue(senderKey, out var channelNum))
                    {
                        var channelData = BuildChannelData(channelNum, result.Buffer);
                        await SendToClientAsync(allocation, channelData).ConfigureAwait(false);
                    }
                    else
                    {

                        var indication = new STUNMessage(STUNMessageTypesEnum.DataIndication);
                        indication.AddXORPeerAddressAttribute(
                            result.RemoteEndPoint.Address, result.RemoteEndPoint.Port);
                        indication.Attributes.Add(new STUNAttribute(
                            STUNAttributeTypesEnum.Data, result.Buffer));
                        var bytes = indication.ToByteBuffer(null, false);
                        await SendToClientAsync(allocation, bytes).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "UDP relay loop ended for allocation {Id}. {ErrorMessage}",
                    allocation.Id, ex.Message);
            }
        }

        private static async Task SendToClientAsync(TurnAllocation allocation, byte[] data)
        {
            try
            {
                if (allocation.TcpStream != null)
                {
                    await allocation.TcpStream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
                }
                else if (allocation.UdpControlSocket != null && allocation.UdpClientEndPoint != null)
                {
                    await allocation.UdpControlSocket.SendAsync(
                        data, data.Length, allocation.UdpClientEndPoint).ConfigureAwait(false);
                }
            }
            catch { }
        }

        #endregion

        #region Helpers

        private static bool HasPermission(TurnAllocation allocation, string peerIp)
        {
            return HasPermission(allocation, peerIp, DateTime.UtcNow);
        }

        private static bool HasPermission(TurnAllocation allocation, string peerIp, DateTime now)
        {
            if (allocation.Permissions.TryGetValue(peerIp, out var expiry))
            {
                if (now < expiry)
                {
                    return true;
                }

                allocation.Permissions.TryRemove(peerIp, out _);
            }
            return false;
        }

        private static bool HasAttribute(STUNMessage message, STUNAttributeTypesEnum attributeType)
        {
            foreach (var attribute in message.Attributes)
            {
                if (attribute.AttributeType == attributeType)
                {
                    return true;
                }
            }

            return false;
        }

        private static byte[] BuildChannelData(ushort channelNumber, byte[] data)
        {
            var dataLen = data.Length;
            var padding = (4 - (dataLen % 4)) % 4;
            var buf = new byte[4 + dataLen + padding];
            buf[0] = (byte)(channelNumber >> 8);
            buf[1] = (byte)(channelNumber & 0xFF);
            buf[2] = (byte)(dataLen >> 8);
            buf[3] = (byte)(dataLen & 0xFF);
            Buffer.BlockCopy(data, 0, buf, 4, dataLen);
            return buf;
        }

        private static string GenerateNonce()
        {
            var nonceBytes = new byte[16];
#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
            RandomNumberGenerator.Fill(nonceBytes);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonceBytes);
            }
#endif

#if NET5_0_OR_GREATER
            return Convert.ToHexString(nonceBytes).ToLowerInvariant();
#else
            var sb = new StringBuilder(nonceBytes.Length * 2);
            for (int i = 0; i < nonceBytes.Length; i++)
            {
                sb.Append(nonceBytes[i].ToString("x2"));
            }
            return sb.ToString();
#endif
        }

        private void CleanExpiredAllocations(object state)
        {
            var now = DateTime.UtcNow;
            foreach (var kvp in _allocations)
            {
                var allocation = kvp.Value;

                if (now > allocation.Expiry)
                {
                    if (_allocations.TryRemove(kvp.Key, out var removed))
                    {
                        removed.Dispose();
                        logger.LogInformation("TURN allocation expired and removed: {Id}.", kvp.Key);
                    }
                }
                else
                {

                    foreach (var perm in allocation.Permissions)
                    {
                        if (now > perm.Value)
                        {
                            allocation.Permissions.TryRemove(perm.Key, out _);
                        }
                    }
                }
            }
        }

        #endregion
    }
}
