
















using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers.Binary;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Digests;
using SIPSorcery.Sys;

namespace SIPSorcery.Net;

public class TurnClient
{
    private const int MAX_ALLOCATE_ATTEMPTS = 5;




    private const uint ALLOCATION_TIME_TO_EXPIRY_SECONDS = 600;

    private const int ALLOCATE_RETRY_PERIOD_MILLISECONDS = 1000;

    private const int ALLOCATE_DEFAULT_TIMEOUT_MILLISECONDS = 5000;

    private const int ALLOCATE_DEFAULT_LIFETIME_SECONDS = 600;

    private const int PERMISSION_DEFAULT_LIFETIME_SECONDS = 300;

    private const int GRACE_RENEWAL_SECONDS = 10;

    private static readonly ILogger logger = LogFactory.CreateLogger<TurnClient>();

    private readonly IceServerResolver _iceServerResolver = new IceServerResolver();

    private IceServer _iceServer;
    public IceServer IceServer => _iceServer;

    private RTPChannel _rtpChannel;

    private bool _allocateRequestSent = false;
    private int _allocateRetries = 0;

    private IPEndPoint _peerEndPoint;

    private Timer _allocateRenewalTimer = null;

    private Timer _permissionsRenewalTimer = null;









    public event Action<STUNMessage, IPEndPoint, bool> OnStunMessageSent;

    public TurnClient(string turnServerUrl)
    {
        _iceServerResolver.InitialiseIceServers([RTCIceServer.Parse(turnServerUrl)], RTCIceTransportPolicy.all);
    }

    public void SetRtpChannel(RTPChannel rtpChannel)
    {
        if (_rtpChannel != null)
        {
            _rtpChannel.OnStunMessageReceived -= GotStunResponse;
            _rtpChannel.OnClosed -= OnClosed;
        }

        _rtpChannel = rtpChannel;
        _rtpChannel.OnStunMessageReceived += GotStunResponse;
        _rtpChannel.OnClosed += OnClosed;
    }




    public async Task<IPEndPoint> GetRelayEndPoint(int timeoutMilliseconds = ALLOCATE_DEFAULT_TIMEOUT_MILLISECONDS, CancellationToken cancellationToken = default)
    {
        if (_iceServer?.RelayEndPoint != null)
        {

            return _iceServer.RelayEndPoint;
        }

        if (_iceServer == null)
        {
            await _iceServerResolver.WaitForAllIceServersAsync(TimeSpan.FromMilliseconds(timeoutMilliseconds));

            foreach (var iceServer in _iceServerResolver.IceServers)
            {
                _iceServer = iceServer.Value;
                break;
            }
        }

        if(_iceServer == null)
        {
            logger.LogWarning("No TURN server was available to allocate a relay endpoint.");
            return null;
        }
        else if (_iceServer.ServerEndPoint == null)
        {
            logger.LogWarning("The TURN server end point was not available for {uri}.", _iceServer?.Uri);
            return null;
        }

        var start = DateTime.Now;

        while (_iceServer.RelayEndPoint == null && !cancellationToken.IsCancellationRequested)
        {
            if ((int)DateTime.Now.Subtract(start).TotalMilliseconds > timeoutMilliseconds)
            {
                logger.LogWarning("TURN allocate timed out.");
                break;
            }

            if (!_allocateRequestSent ||
                (DateTime.Now.Subtract(_iceServer.LastRequestSentAt).TotalMilliseconds > 500 &&
                 _iceServer.LastResponseReceivedAt < _iceServer.LastRequestSentAt))
            {
                if (_allocateRetries >= MAX_ALLOCATE_ATTEMPTS)
                {
                    logger.LogWarning("TURN allocate max retries reached.");
                    break;
                }

                var sendRes = SendTurnAllocateRequest(_iceServer);

                _allocateRequestSent = true;
                _allocateRetries++;

                if (sendRes != SocketError.Success)
                {
                    logger.LogWarning("TURN allocate send error {Result}.", sendRes);
                }
            }

            await Task.Delay(ALLOCATE_RETRY_PERIOD_MILLISECONDS, cancellationToken).ConfigureAwait(false);
        }

        if(_iceServer.RelayEndPoint == null)
        {
            logger.LogWarning("TURN allocate failed to get a relay endpoint.");
        }
        else
        {
            logger.LogInformation("TURN allocate succeeded, relay endpoint is {relayEndPoint}.", _iceServer.RelayEndPoint);
        }

        return _iceServer?.RelayEndPoint;
    }

    public SocketError CreatePermission(IPEndPoint remoteEndPoint)
    {
        _peerEndPoint = remoteEndPoint;

        return SendTurnCreatePermissionsRequest(_iceServer, remoteEndPoint);
    }











    private void GotStunResponse(STUNMessage stunResponse, IPEndPoint remoteEndPoint, bool wasRelayed)
    {
        string txID = Encoding.ASCII.GetString(stunResponse.Header.TransactionId);


        if (_iceServer.TransactionID == txID)
        {

            _iceServer.LastResponseReceivedAt = DateTime.Now;
            _iceServer.OutstandingRequestsSent = 0;

            if (stunResponse.Header.MessageType == STUNMessageTypesEnum.AllocateSuccessResponse)
            {
                logger.LogInformation("TURN client received a success response for an Allocate request to {Uri} from {remoteEP}.", _iceServer.Uri, remoteEndPoint);

                _iceServer.ErrorResponseCount = 0;

                logger.LogDebug("TURN allocate success response received for ICE server check to {Uri}.", _iceServer.Uri);

                var mappedAddrAttr = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.XORMappedAddress);

                if (mappedAddrAttr != null)
                {
                    _iceServer.ServerReflexiveEndPoint = (mappedAddrAttr as STUNXORAddressAttribute).GetIPEndPoint();
                }

                var mappedRelayAddrAttr = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.XORRelayedAddress);

                if (mappedRelayAddrAttr != null)
                {
                    _iceServer.RelayEndPoint = (mappedRelayAddrAttr as STUNXORAddressAttribute).GetIPEndPoint();
                }

                var lifetime = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.Lifetime);

                ScheduleAllocateRefresh(lifetime);
            }
            else if (stunResponse.Header.MessageType == STUNMessageTypesEnum.AllocateErrorResponse)
            {
                logger.LogWarning("TURN client received an error response for an Allocate request to {Uri} from {remoteEP}.", _iceServer.Uri, remoteEndPoint);

                _iceServer.ErrorResponseCount++;

                var errCodeAttribute = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.ErrorCode) as STUNErrorCodeAttribute;
                if (errCodeAttribute != null)
                {
                    var alternateServerAttribute = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.AlternateServer) as STUNAddressAttribute;

                    if (errCodeAttribute.ErrorCode == IceServer.STUN_UNAUTHORISED_ERROR_CODE || errCodeAttribute.ErrorCode == IceServer.STUN_STALE_NONCE_ERROR_CODE)
                    {
                        logger.LogWarning("TURN client error response code {errorCode} for an Allocate request to {Uri} from {remoteEP}.", errCodeAttribute.ErrorCode, _iceServer.Uri, remoteEndPoint);


                        SetAuthenticationFields(stunResponse);


                        _iceServer.GenerateNewTransactionID();

                        _iceServer.ErrorResponseCount = 1;

                        SendTurnAllocateRequest(_iceServer);
                    }
                    else if (alternateServerAttribute != null)
                    {
                        _iceServer.ServerEndPoint = new IPEndPoint(alternateServerAttribute.Address, alternateServerAttribute.Port);

                        logger.LogWarning("TURN client received an alternate respose for an Allocate request to {Uri}, changed server url to {ServerEndPoint}.", _iceServer.Uri, _iceServer.ServerEndPoint);


                        _iceServer.GenerateNewTransactionID();

                        _iceServer.ErrorResponseCount = 1;
                    }
                    else
                    {
                        logger.LogWarning("TURN client received an error response for an Allocate request to {Uri}, error {ErrorCode} {ReasonPhrase}.", _iceServer.Uri, errCodeAttribute.ErrorCode, errCodeAttribute.ReasonPhrase);
                    }
                }
                else
                {
                    logger.LogWarning("TURN client received an error response for an Allocate request to {Uri}.", _iceServer.Uri);
                }
            }
            else if (stunResponse.Header.MessageType == STUNMessageTypesEnum.CreatePermissionSuccessResponse)
            {
                logger.LogInformation("TURN client received a success response for a CreatePermission request to {Uri} from {remoteEP}.", _iceServer.Uri, remoteEndPoint);

                var permissionLifetime = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.Lifetime);
                TimeSpan permissionDuration = TimeSpan.FromSeconds(PERMISSION_DEFAULT_LIFETIME_SECONDS);

                if (permissionLifetime != null)
                {
                    permissionDuration = TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(permissionLifetime.Value));

                    logger.LogDebug("TURN permission lifetime attribute value {lifetimeSeconds}s.", permissionDuration.TotalSeconds);
                }
                else
                {
                    logger.LogDebug("TURN permission using default lifetime of {lifetimeSeconds}s.", PERMISSION_DEFAULT_LIFETIME_SECONDS);
                }

                var renewalTime = DateTime.Now.Add(permissionDuration).Subtract(TimeSpan.FromSeconds(GRACE_RENEWAL_SECONDS));
                var renewalMilliseconds = GetTimerDueTimeMilliseconds(renewalTime.Subtract(DateTime.Now));

                logger.LogInformation("Scheduling TURN create permission refresh for server {RelayEndPoint} and peer {peer}, allocation expires in {renewalMilliseconds}ms, renew at {renewalTime}.", _iceServer.RelayEndPoint, _peerEndPoint, renewalMilliseconds, renewalTime.ToString("o"));

                _permissionsRenewalTimer?.Dispose();
                _permissionsRenewalTimer = new Timer((e) =>
                {
                    _iceServer.GenerateNewTransactionID();
                    SendTurnCreatePermissionsRequest(_iceServer, _peerEndPoint);
                }, null, renewalMilliseconds, -1);
            }
            else if (stunResponse.Header.MessageType == STUNMessageTypesEnum.CreatePermissionErrorResponse)
            {
                logger.LogWarning("TURN client received an error response for a Create Permission request to {Uri} from {remoteEP}.", _iceServer.Uri, remoteEndPoint);

                _iceServer.ErrorResponseCount++;

                var errCodeAttribute = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.ErrorCode) as STUNErrorCodeAttribute;
                if (errCodeAttribute != null)
                {
                    if (errCodeAttribute.ErrorCode == IceServer.STUN_UNAUTHORISED_ERROR_CODE || errCodeAttribute.ErrorCode == IceServer.STUN_STALE_NONCE_ERROR_CODE)
                    {
                        logger.LogWarning("TURN client error response code {errorCode} for a Create Permission request to {Uri} from {remoteEP}.", errCodeAttribute.ErrorCode, _iceServer.Uri, remoteEndPoint);


                        SetAuthenticationFields(stunResponse);


                        _iceServer.GenerateNewTransactionID();

                        _iceServer.ErrorResponseCount = 1;

                        SendTurnCreatePermissionsRequest(_iceServer, _peerEndPoint);
                    }
                    else
                    {
                        logger.LogWarning("TURN client received an error response for a Create Permission request to {Uri}, error {ErrorCode} {ReasonPhrase}.", _iceServer.Uri, errCodeAttribute.ErrorCode, errCodeAttribute.ReasonPhrase);
                    }
                }
                else
                {
                    logger.LogWarning("TURN client received an error response for a Create Permission request to {Uri}.", _iceServer.Uri);
                }
            }
            else if (stunResponse.Header.MessageType == STUNMessageTypesEnum.RefreshSuccessResponse)
            {
                logger.LogInformation("TURN client received a success response for a Refresh request to {Uri} from {remoteEP}.", _iceServer.Uri, remoteEndPoint);

                ScheduleAllocateRefresh(stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.Lifetime));
            }
            else
            {
                logger.LogWarning("An unrecognised STUN {MessageType} response for an ICE server check was received from {RemoteEndPoint}.", stunResponse.Header.MessageType, remoteEndPoint);
                _iceServer.ErrorResponseCount++;
            }
        }
    }

    private void ScheduleAllocateRefresh(STUNAttribute lifetimeAttribute)
    {
        if(_rtpChannel == null || _rtpChannel.IsClosed)
        {
            logger.LogWarning("RTP channel is not set or closed, cannot schedule TURN Allocate refresh.");
            return;
        }

        if (lifetimeAttribute != null)
        {
            var lifetimeSpan = TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(lifetimeAttribute.Value));

            logger.LogDebug("TURN allocate lifetime attribute value {lifetimeSeconds}s.", lifetimeSpan.TotalSeconds);

            _iceServer.TurnTimeToExpiry = DateTime.Now + lifetimeSpan;
        }
        else
        {
            logger.LogDebug("TURN allocate using default lifetime of {lifetimeSeconds}s.", ALLOCATE_DEFAULT_LIFETIME_SECONDS);

            _iceServer.TurnTimeToExpiry = DateTime.Now + TimeSpan.FromSeconds(ALLOCATE_DEFAULT_LIFETIME_SECONDS);
        }

        var renewalMilliseconds = GetTimerDueTimeMilliseconds(
            _iceServer.TurnTimeToExpiry.Subtract(DateTime.Now).Subtract(TimeSpan.FromSeconds(GRACE_RENEWAL_SECONDS)));
        var renewalTime = _iceServer.TurnTimeToExpiry;

        logger.LogInformation("Scheduling TURN client allocated refresh for server {RelayEndPoint} at {Uri}, allocation expires at {Expiry}.",
            _iceServer.RelayEndPoint, _iceServer.Uri, renewalTime.ToString("o"));

        _allocateRenewalTimer?.Dispose();
        _allocateRenewalTimer = new Timer((e) =>
        {
            _iceServer.GenerateNewTransactionID();
            SendTurnRefreshRequest(_iceServer);
        }, null, renewalMilliseconds, -1);
    }





    private void SetAuthenticationFields(STUNMessage stunResponse)
    {

        var nonceAttribute = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.Nonce);
        _iceServer.Nonce = nonceAttribute?.Value;

        var realmAttribute = stunResponse.GetFirstAttribute(STUNAttributeTypesEnum.Realm);
        _iceServer.Realm = realmAttribute?.Value;
    }






    private SocketError SendTurnAllocateRequest(IceServer iceServer)
    {
        if (_rtpChannel == null || _rtpChannel.IsClosed)
        {
            logger.LogWarning("RTP channel is not set or closed, cannot send TURN Allocate request.");
            return SocketError.NotConnected;
        }

        iceServer.OutstandingRequestsSent += 1;
        iceServer.LastRequestSentAt = DateTime.Now;

        STUNMessage allocateRequest = new STUNMessage(STUNMessageTypesEnum.Allocate);
        allocateRequest.Header.TransactionId = Encoding.ASCII.GetBytes(iceServer.TransactionID);
        allocateRequest.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.RequestedTransport, STUNAttributeConstants.UdpTransportType));
        allocateRequest.Attributes.Add(
            new STUNAttribute(STUNAttributeTypesEnum.RequestedAddressFamily,
            iceServer.ServerEndPoint.AddressFamily == AddressFamily.InterNetwork ?
            STUNAttributeConstants.IPv4AddressFamily : STUNAttributeConstants.IPv6AddressFamily));

        byte[] allocateReqBytes = null;

        if (iceServer.Nonce != null && iceServer.Realm != null && iceServer._username != null && iceServer._password != null)
        {
            allocateReqBytes = GetAuthenticatedStunRequest(allocateRequest, iceServer._username, iceServer.Realm, iceServer._password, iceServer.Nonce);
        }
        else
        {
            allocateReqBytes = allocateRequest.ToByteBuffer(null, false);
        }

        var sendResult = _rtpChannel.Send(RTPChannelSocketsEnum.RTP, iceServer.ServerEndPoint, allocateReqBytes);

        if (sendResult != SocketError.Success)
        {
            logger.LogWarning("Error sending TURN Allocate request {OutstandingRequestsSent} for {Uri} to {ServerEndPoint}. {SendResult}.",
                iceServer.OutstandingRequestsSent, iceServer._uri, iceServer.ServerEndPoint, sendResult);
        }
        else
        {
            OnStunMessageSent?.Invoke(allocateRequest, iceServer.ServerEndPoint, false);
        }

        return sendResult;
    }













    private SocketError SendTurnCreatePermissionsRequest(IceServer iceServer, IPEndPoint peerEndPoint)
    {
        if(_rtpChannel == null || _rtpChannel.IsClosed)
        {
            logger.LogWarning("RTP channel is not set or closed, cannot send TURN Create Permissions request.");
            return SocketError.NotConnected;
        }

        STUNMessage permissionsRequest = new STUNMessage(STUNMessageTypesEnum.CreatePermission);
        permissionsRequest.Header.TransactionId = Encoding.ASCII.GetBytes(iceServer.TransactionID);
        permissionsRequest.Attributes.Add(new STUNXORAddressAttribute(STUNAttributeTypesEnum.XORPeerAddress, peerEndPoint.Port, peerEndPoint.Address, permissionsRequest.Header.TransactionId));

        byte[] createPermissionReqBytes = null;

        if (iceServer.Nonce != null && iceServer.Realm != null && iceServer._username != null && iceServer._password != null)
        {
            createPermissionReqBytes = GetAuthenticatedStunRequest(permissionsRequest, iceServer._username, iceServer.Realm, iceServer._password, iceServer.Nonce);
        }
        else
        {
            createPermissionReqBytes = permissionsRequest.ToByteBuffer(null, false);
        }

        var sendResult = _rtpChannel.Send(RTPChannelSocketsEnum.RTP, iceServer.ServerEndPoint, createPermissionReqBytes);

        if (sendResult != SocketError.Success)
        {
            logger.LogWarning("Error sending TURN Create Permissions request {OutstandingRequestsSent} for {Uri} to {ServerEndPoint}. {SendResult}.",
                iceServer.OutstandingRequestsSent, iceServer._uri, iceServer.ServerEndPoint, sendResult);
        }
        else
        {
            OnStunMessageSent?.Invoke(permissionsRequest, iceServer.ServerEndPoint, false);
        }

        return sendResult;
    }










    private SocketError SendTurnRefreshRequest(IceServer iceServer)
    {
        iceServer.OutstandingRequestsSent += 1;
        iceServer.LastRequestSentAt = DateTime.Now;

        STUNMessage allocateRequest = new STUNMessage(STUNMessageTypesEnum.Refresh);
        allocateRequest.Header.TransactionId = Encoding.ASCII.GetBytes(iceServer.TransactionID);
        allocateRequest.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Lifetime, ALLOCATION_TIME_TO_EXPIRY_SECONDS));

        allocateRequest.Attributes.Add(
            new STUNAttribute(STUNAttributeTypesEnum.RequestedAddressFamily,
            iceServer.ServerEndPoint.AddressFamily == AddressFamily.InterNetwork ?
            STUNAttributeConstants.IPv4AddressFamily : STUNAttributeConstants.IPv6AddressFamily));

        byte[] allocateReqBytes = null;

        if (iceServer.Nonce != null && iceServer.Realm != null && iceServer._username != null && iceServer._password != null)
        {
            allocateReqBytes = GetAuthenticatedStunRequest(allocateRequest, iceServer._username, iceServer.Realm, iceServer._password, iceServer.Nonce);
        }
        else
        {
            allocateReqBytes = allocateRequest.ToByteBuffer(null, false);
        }

        var sendResult = _rtpChannel.Send(RTPChannelSocketsEnum.RTP, iceServer.ServerEndPoint, allocateReqBytes);

        if (sendResult != SocketError.Success)
        {
            logger.LogWarning("Error sending TURN Refresh request {OutstandingRequestsSent} for {Uri} to {ServerEndPoint}. {SendResult}.",
                iceServer.OutstandingRequestsSent, iceServer._uri, iceServer.ServerEndPoint, sendResult);
        }
        else
        {
            OnStunMessageSent?.Invoke(allocateRequest, iceServer.ServerEndPoint, false);
        }

        return sendResult;
    }





    private byte[] GetAuthenticatedStunRequest(STUNMessage stunRequest, string username, byte[] realm, string password, byte[] nonce)
    {
        stunRequest.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Nonce, nonce));
        stunRequest.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Realm, realm));
        stunRequest.AddUsernameAttribute(username);


        string key = $"{username}:{Encoding.UTF8.GetString(realm)}:{password}";
        var buffer = Encoding.UTF8.GetBytes(key);
        var md5Digest = new MD5Digest();
        var hash = new byte[md5Digest.GetDigestSize()];

        md5Digest.BlockUpdate(buffer, 0, buffer.Length);
        md5Digest.DoFinal(hash, 0);

        return stunRequest.ToByteBuffer(hash, true);
    }

    private void OnClosed(string closeReason)
    {
        if (_rtpChannel != null)
        {
            _rtpChannel.OnStunMessageReceived -= GotStunResponse;
            _rtpChannel.OnClosed -= OnClosed;
        }

        _allocateRenewalTimer?.Dispose();
        _permissionsRenewalTimer?.Dispose();
    }

    private static int GetTimerDueTimeMilliseconds(TimeSpan dueTime)
    {
        if (dueTime <= TimeSpan.Zero)
        {
            return 0;
        }

        return dueTime.TotalMilliseconds >= int.MaxValue
            ? int.MaxValue
            : Convert.ToInt32(dueTime.TotalMilliseconds);
    }
}
