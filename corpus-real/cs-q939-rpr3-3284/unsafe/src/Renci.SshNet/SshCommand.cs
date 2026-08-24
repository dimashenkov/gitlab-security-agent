#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet.Channels;
using Renci.SshNet.Common;
using Renci.SshNet.Messages.Connection;
using Renci.SshNet.Messages.Transport;

namespace Renci.SshNet
{



    public sealed class SshCommand : IDisposable
    {
        private readonly ISession _session;
        private readonly Encoding _encoding;

        private IChannelSession _channel;
        private TaskCompletionSource<object>? _tcs;
        private CancellationTokenSource? _cts;
        private CancellationTokenRegistration _tokenRegistration;
        private string? _stdOut;
        private string? _stdErr;
        private bool _hasError;
        private bool _isDisposed;
        private ChannelInputStream? _inputStream;
        private TimeSpan _commandTimeout;




        private CancellationToken _userToken;





        private bool _cancellationRequested;

        private int _exitStatus;
        private volatile bool _haveExitStatus;




        public string CommandText { get; private set; }







        public TimeSpan CommandTimeout
        {
            get
            {
                return _commandTimeout;
            }
            set
            {
                value.EnsureValidTimeout(nameof(CommandTimeout));

                _commandTimeout = value;
            }
        }











        public int? ExitStatus
        {
            get
            {
                return _haveExitStatus ? _exitStatus : null;
            }
        }










        public string? ExitSignal { get; private set; }




        public Stream OutputStream { get; private set; }




        public Stream ExtendedOutputStream { get; private set; }































        public Stream CreateInputStream()
        {
            if (!_channel.IsOpen)
            {
                throw new InvalidOperationException("The input stream can be used only during execution.");
            }

            if (_inputStream != null)
            {
                throw new InvalidOperationException("The input stream already exists.");
            }

            _inputStream = new ChannelInputStream(_channel);
            return _inputStream;
        }




        public string Result
        {
            get
            {
                if (_stdOut is not null)
                {
                    return _stdOut;
                }

                if (_tcs is null)
                {
                    return string.Empty;
                }

                using (var sr = new StreamReader(OutputStream, _encoding))
                {
                    return _stdOut = sr.ReadToEnd();
                }
            }
        }





        public string Error
        {
            get
            {
                if (_stdErr is not null)
                {
                    return _stdErr;
                }

                if (_tcs is null || !_hasError)
                {
                    return string.Empty;
                }

                using (var sr = new StreamReader(ExtendedOutputStream, _encoding))
                {
                    return _stdErr = sr.ReadToEnd();
                }
            }
        }








        internal SshCommand(ISession session, string commandText, Encoding encoding)
        {
            ArgumentNullException.ThrowIfNull(session);
            ArgumentNullException.ThrowIfNull(commandText);
            ArgumentNullException.ThrowIfNull(encoding);

            _session = session;
            CommandText = commandText;
            _encoding = encoding;
            CommandTimeout = Timeout.InfiniteTimeSpan;
            OutputStream = new PipeStream();
            ExtendedOutputStream = new PipeStream();
            _session.Disconnected += Session_Disconnected;
            _session.ErrorOccured += Session_ErrorOccurred;
            _channel = _session.CreateChannelSession();
        }













#pragma warning disable CA1849
        public Task ExecuteAsync(CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            if (_tcs is not null)
            {
                if (!_tcs.Task.IsCompleted)
                {
                    throw new InvalidOperationException("Asynchronous operation is already in progress.");
                }

                UnsubscribeFromChannelEvents(dispose: true);

                OutputStream.Dispose();
                ExtendedOutputStream.Dispose();




                OutputStream = new PipeStream();
                ExtendedOutputStream = new PipeStream();
                _channel = _session.CreateChannelSession();
            }

            _exitStatus = default;
            _haveExitStatus = false;
            ExitSignal = null;
            _stdOut = null;
            _stdErr = null;
            _hasError = false;
            _tokenRegistration.Dispose();
            _tokenRegistration = default;
            _cts?.Dispose();
            _cts = null;
            _cancellationRequested = false;

            _tcs = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
            _userToken = cancellationToken;

            _channel.DataReceived += Channel_DataReceived;
            _channel.ExtendedDataReceived += Channel_ExtendedDataReceived;
            _channel.RequestReceived += Channel_RequestReceived;
            _channel.Closed += Channel_Closed;
            _channel.Open();

            _ = _channel.SendExecRequest(CommandText);

            if (CommandTimeout != Timeout.InfiniteTimeSpan)
            {
                _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                _cts.CancelAfter(CommandTimeout);
                cancellationToken = _cts.Token;
            }

            if (cancellationToken.CanBeCanceled)
            {
                _tokenRegistration = cancellationToken.Register(static cmd =>
                {
                    try
                    {
                        ((SshCommand)cmd!).CancelAsync();
                    }
                    catch
                    {

                    }
                },
                this);
            }

            return _tcs.Task;
        }
#pragma warning restore CA1849












        public IAsyncResult BeginExecute()
        {
            return BeginExecute(callback: null, state: null);
        }













        public IAsyncResult BeginExecute(AsyncCallback? callback)
        {
            return BeginExecute(callback, state: null);
        }














        public IAsyncResult BeginExecute(AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(ExecuteAsync(), callback, state);
        }












        public IAsyncResult BeginExecute(string commandText, AsyncCallback? callback, object? state)
        {
            ArgumentNullException.ThrowIfNull(commandText);

            CommandText = commandText;

            return BeginExecute(callback, state);
        }








        public string EndExecute(IAsyncResult asyncResult)
        {
            var executeTask = TaskToAsyncResult.Unwrap(asyncResult);

            if (executeTask != _tcs?.Task)
            {
                throw new ArgumentException("Argument does not correspond to the currently executing command.", nameof(asyncResult));
            }

            executeTask.GetAwaiter().GetResult();

            return Result;
        }
























        public void CancelAsync(bool forceKill = false, int millisecondsTimeout = 500)
        {
            if (_tcs is null)
            {
                throw new InvalidOperationException("Command has not been started.");
            }

            if (_tcs.Task.IsCompleted)
            {
                return;
            }

            _cancellationRequested = true;
            Interlocked.MemoryBarrier();

            try
            {

                if (_channel?.SendSignalRequest(forceKill ? "KILL" : "TERM") is null)
                {

                    return;
                }






                _ = _tcs.Task.Wait(millisecondsTimeout);
            }
            catch (AggregateException)
            {


            }
            finally
            {
                SetAsyncComplete();
            }
        }







        public string Execute()
        {
            ExecuteAsync().GetAwaiter().GetResult();

            return Result;
        }








        public string Execute(string commandText)
        {
            CommandText = commandText;

            return Execute();
        }

        private void Session_Disconnected(object? sender, EventArgs e)
        {
            _ = _tcs?.TrySetException(new SshConnectionException("An established connection was aborted by the software in your host machine.", DisconnectReason.ConnectionLost));

            SetAsyncComplete(setResult: false);
        }

        private void Session_ErrorOccurred(object? sender, ExceptionEventArgs e)
        {
            _ = _tcs?.TrySetException(e.Exception);

            SetAsyncComplete(setResult: false);
        }

        private void SetAsyncComplete(bool setResult = true)
        {
            Interlocked.MemoryBarrier();

            if (setResult)
            {
                Debug.Assert(_tcs is not null, "Should only be completing the task if we've started one.");

                if (_userToken.IsCancellationRequested)
                {
                    _ = _tcs.TrySetCanceled(_userToken);
                }
                else if (_cts?.Token.IsCancellationRequested == true)
                {
                    _ = _tcs.TrySetException(new SshOperationTimeoutException($"Command '{CommandText}' timed out. ({nameof(CommandTimeout)}: {CommandTimeout})."));
                }
                else if (_cancellationRequested)
                {
                    _ = _tcs.TrySetCanceled();
                }
                else
                {
                    _ = _tcs.TrySetResult(null!);
                }
            }




            UnsubscribeFromChannelEvents(dispose: false);

            OutputStream.Dispose();
            ExtendedOutputStream.Dispose();
        }

        private void Channel_Closed(object? sender, ChannelEventArgs e)
        {
            SetAsyncComplete();
        }

        private void Channel_RequestReceived(object? sender, ChannelRequestEventArgs e)
        {
            if (e.Info is ExitStatusRequestInfo exitStatusInfo)
            {
                _exitStatus = (int)exitStatusInfo.ExitStatus;
                _haveExitStatus = true;

                Debug.Assert(!exitStatusInfo.WantReply, "exit-status is want_reply := false by definition.");
            }
            else if (e.Info is ExitSignalRequestInfo exitSignalInfo)
            {
                ExitSignal = exitSignalInfo.SignalName;

                Debug.Assert(!exitSignalInfo.WantReply, "exit-signal is want_reply := false by definition.");
            }
            else if (e.Info.WantReply && sender is IChannel { RemoteChannelNumber: uint remoteChannelNumber })
            {
                var replyMessage = new ChannelFailureMessage(remoteChannelNumber);
                _session.SendMessage(replyMessage);
            }
        }

        private void Channel_ExtendedDataReceived(object? sender, ChannelExtendedDataEventArgs e)
        {
            ExtendedOutputStream.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);

            if (e.DataTypeCode == 1)
            {
                _hasError = true;
            }
        }

        private void Channel_DataReceived(object? sender, ChannelDataEventArgs e)
        {
            OutputStream.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
        }





        private void UnsubscribeFromChannelEvents(bool dispose)
        {
            var channel = _channel;



            channel.DataReceived -= Channel_DataReceived;
            channel.ExtendedDataReceived -= Channel_ExtendedDataReceived;
            channel.RequestReceived -= Channel_RequestReceived;
            channel.Closed -= Channel_Closed;

            if (dispose)
            {
                channel.Dispose();
            }
        }




        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }





        private void Dispose(bool disposing)
        {
            if (_isDisposed)
            {
                return;
            }

            if (disposing)
            {


                _session.Disconnected -= Session_Disconnected;
                _session.ErrorOccured -= Session_ErrorOccurred;



                UnsubscribeFromChannelEvents(dispose: true);

                _inputStream?.Dispose();
                _inputStream = null;

                OutputStream.Dispose();
                ExtendedOutputStream.Dispose();

                _tokenRegistration.Dispose();
                _tokenRegistration = default;
                _cts?.Dispose();
                _cts = null;

                if (_tcs is { Task.IsCompleted: false } tcs)
                {

                    _ = tcs.TrySetException(new ObjectDisposedException(GetType().FullName));
                }

                _isDisposed = true;
            }
        }
    }
}
