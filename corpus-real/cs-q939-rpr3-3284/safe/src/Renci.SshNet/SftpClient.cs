#nullable enable
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Renci.SshNet.Abstractions;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;
using Renci.SshNet.Sftp.Requests;

namespace Renci.SshNet
{



    public class SftpClient : BaseClient, ISftpClient
    {
        private static readonly Encoding Utf8NoBOM = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);





        private ISftpSession? _sftpSession;




        private int _operationTimeout;




        private uint _bufferSize;









        public TimeSpan OperationTimeout
        {
            get
            {
                return TimeSpan.FromMilliseconds(_operationTimeout);
            }
            set
            {
                _operationTimeout = value.AsTimeout(nameof(OperationTimeout));

                if (_sftpSession is { } sftpSession)
                {
                    sftpSession.OperationTimeout = _operationTimeout;
                }
            }
        }
































        public uint BufferSize
        {
            get
            {
                CheckDisposed();
                return _bufferSize;
            }
            set
            {
                CheckDisposed();
                _bufferSize = value;
            }
        }









        public override bool IsConnected
        {
            get
            {
                return base.IsConnected && _sftpSession?.IsOpen == true;
            }
        }






        public string WorkingDirectory
        {
            get
            {
                CheckDisposed();

                if (_sftpSession is null)
                {
                    throw new SshConnectionException("Client not connected.");
                }

                return _sftpSession.WorkingDirectory;
            }
        }






        public int ProtocolVersion
        {
            get
            {
                CheckDisposed();

                if (_sftpSession is null)
                {
                    throw new SshConnectionException("Client not connected.");
                }

                return (int)_sftpSession.ProtocolVersion;
            }
        }







        internal ISftpSession? SftpSession
        {
            get { return _sftpSession; }
        }

        #region Constructors






        public SftpClient(ConnectionInfo connectionInfo)
            : this(connectionInfo, ownsConnectionInfo: false)
        {
        }











        public SftpClient(string host, int port, string username, string password)
            : this(new PasswordConnectionInfo(host, port, username, password), ownsConnectionInfo: true)
        {
        }









        public SftpClient(string host, string username, string password)
            : this(host, ConnectionInfo.DefaultPort, username, password)
        {
        }











        public SftpClient(string host, int port, string username, params IPrivateKeySource[] keyFiles)
            : this(new PrivateKeyConnectionInfo(host, port, username, keyFiles), ownsConnectionInfo: true)
        {
        }









        public SftpClient(string host, string username, params IPrivateKeySource[] keyFiles)
            : this(host, ConnectionInfo.DefaultPort, username, keyFiles)
        {
        }











        private SftpClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo)
            : this(connectionInfo, ownsConnectionInfo, new ServiceFactory())
        {
        }













        internal SftpClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo, IServiceFactory serviceFactory)
            : base(connectionInfo, ownsConnectionInfo, serviceFactory)
        {
            _operationTimeout = Timeout.Infinite;
            _bufferSize = 1024 * 32;
        }

        #endregion Constructors











        public void ChangeDirectory(string path)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            _sftpSession.ChangeDirectory(path);
        }













        public Task ChangeDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            return _sftpSession.ChangeDirectoryAsync(path, cancellationToken);
        }












        public void ChangePermissions(string path, short mode)
        {
            var file = Get(path);
            file.SetPermissions(mode);
        }










        public void CreateDirectory(string path)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            _sftpSession.RequestMkDir(fullPath);
        }












        public async Task CreateDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);

            await _sftpSession.RequestMkDirAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }











        public void DeleteDirectory(string path)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            _sftpSession.RequestRmDir(fullPath);
        }


        public async Task DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);

            await _sftpSession.RequestRmDirAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }











        public void DeleteFile(string path)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            _sftpSession.RequestRemove(fullPath);
        }


        public async Task DeleteFileAsync(string path, CancellationToken cancellationToken)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);
            await _sftpSession.RequestRemoveAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }











        public void RenameFile(string oldPath, string newPath)
        {
            RenameFile(oldPath, newPath, isPosix: false);
        }












        public void RenameFile(string oldPath, string newPath, bool isPosix)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(oldPath);
            ArgumentNullException.ThrowIfNull(newPath);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var oldFullPath = _sftpSession.GetCanonicalPath(oldPath);

            var newFullPath = _sftpSession.GetCanonicalPath(newPath);

            if (isPosix)
            {
                _sftpSession.RequestPosixRename(oldFullPath, newFullPath);
            }
            else
            {
                _sftpSession.RequestRename(oldFullPath, newFullPath);
            }
        }













        public async Task RenameFileAsync(string oldPath, string newPath, CancellationToken cancellationToken)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(oldPath);
            ArgumentNullException.ThrowIfNull(newPath);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var oldFullPath = await _sftpSession.GetCanonicalPathAsync(oldPath, cancellationToken).ConfigureAwait(false);
            var newFullPath = await _sftpSession.GetCanonicalPathAsync(newPath, cancellationToken).ConfigureAwait(false);
            await _sftpSession.RequestRenameAsync(oldFullPath, newFullPath, cancellationToken).ConfigureAwait(false);
        }











        public void SymbolicLink(string path, string linkPath)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            ArgumentException.ThrowIfNullOrWhiteSpace(linkPath);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            var linkFullPath = _sftpSession.GetCanonicalPath(linkPath);

            _sftpSession.RequestSymLink(fullPath, linkFullPath);
        }















        public IEnumerable<ISftpFile> ListDirectory(string path, Action<int>? listCallback = null)
        {
            CheckDisposed();

            return InternalListDirectory(path, asyncResult: null, listCallback);
        }
















        public async IAsyncEnumerable<ISftpFile> ListDirectoryAsync(string path, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);

            var handle = await _sftpSession.RequestOpenDirAsync(fullPath, cancellationToken).ConfigureAwait(false);
            try
            {
                var basePath = (fullPath[fullPath.Length - 1] == '/') ?
                    fullPath :
                    fullPath + '/';

                while (true)
                {
                    var files = await _sftpSession.RequestReadDirAsync(handle, cancellationToken).ConfigureAwait(false);
                    if (files is null)
                    {
                        break;
                    }

                    foreach (var file in files)
                    {
                        yield return new SftpFile(_sftpSession, basePath + file.Key, file.Value);
                    }
                }
            }
            finally
            {
                await _sftpSession.RequestCloseAsync(handle, cancellationToken).ConfigureAwait(false);
            }
        }












        public IAsyncResult BeginListDirectory(string path, AsyncCallback? asyncCallback, object? state, Action<int>? listCallback = null)
        {
            CheckDisposed();

            var asyncResult = new SftpListDirectoryAsyncResult(asyncCallback, state);

            ThreadAbstraction.ExecuteThread(() =>
            {
                try
                {
                    var result = InternalListDirectory(path, asyncResult, listCallback);

                    asyncResult.SetAsCompleted(result, completedSynchronously: false);
                }
                catch (Exception exp)
                {
                    asyncResult.SetAsCompleted(exp, completedSynchronously: false);
                }
            });

            return asyncResult;
        }









        public IEnumerable<ISftpFile> EndListDirectory(IAsyncResult asyncResult)
        {
            if (asyncResult is not SftpListDirectoryAsyncResult ar || ar.EndInvokeCalled)
            {
                throw new ArgumentException("Either the IAsyncResult object did not come from the corresponding async method on this type, or EndExecute was called multiple times with the same IAsyncResult.");
            }


            return ar.EndInvoke();
        }












        public ISftpFile Get(string path)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            var attributes = _sftpSession.RequestLStat(fullPath);

            return new SftpFile(_sftpSession, fullPath, attributes);
        }














        public async Task<ISftpFile> GetAsync(string path, CancellationToken cancellationToken)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);

            var attributes = await _sftpSession.RequestLStatAsync(fullPath, cancellationToken).ConfigureAwait(false);

            return new SftpFile(_sftpSession, fullPath, attributes);
        }













        public bool Exists(string path)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);




















            try
            {
                _ = _sftpSession.RequestLStat(fullPath);
                return true;
            }
            catch (SftpPathNotFoundException)
            {
                return false;
            }
        }















        public async Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default)
        {
            CheckDisposed();
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);




















            try
            {
                _ = await _sftpSession.RequestLStatAsync(fullPath, cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (SftpPathNotFoundException)
            {
                return false;
            }
        }


        public void DownloadFile(string path, Stream output, Action<ulong>? downloadCallback = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            ArgumentNullException.ThrowIfNull(output);
            CheckDisposed();

            IProgress<DownloadFileProgressReport>? downloadProgress = null;

            if (downloadCallback != null)
            {
                downloadProgress = new ThreadPoolProgress<DownloadFileProgressReport>(r => downloadCallback(r.TotalBytesDownloaded));
            }

            InternalDownloadFile(
                path,
                output,
                asyncResult: null,
                downloadProgress,
                isAsync: false,
                CancellationToken.None).GetAwaiter().GetResult();
        }


        public Task DownloadFileAsync(string path, Stream output, CancellationToken cancellationToken = default)
        {
            return DownloadFileAsync(path, output, downloadProgress: null, cancellationToken);
        }


        public Task DownloadFileAsync(string path, Stream output, IProgress<DownloadFileProgressReport>? downloadProgress, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            ArgumentNullException.ThrowIfNull(output);
            CheckDisposed();

            return InternalDownloadFile(
                path,
                output,
                asyncResult: null,
                downloadProgress,
                isAsync: true,
                cancellationToken);
        }


















        public IAsyncResult BeginDownloadFile(string path, Stream output)
        {
            return BeginDownloadFile(path, output, asyncCallback: null, state: null);
        }



















        public IAsyncResult BeginDownloadFile(string path, Stream output, AsyncCallback? asyncCallback)
        {
            return BeginDownloadFile(path, output, asyncCallback, state: null);
        }


















        public IAsyncResult BeginDownloadFile(string path, Stream output, AsyncCallback? asyncCallback, object? state, Action<ulong>? downloadCallback = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            ArgumentNullException.ThrowIfNull(output);
            CheckDisposed();

            IProgress<DownloadFileProgressReport>? downloadProgress = null;

            if (downloadCallback != null)
            {




                downloadProgress = new ThreadPoolProgress<DownloadFileProgressReport>(r => downloadCallback(r.TotalBytesDownloaded));
            }

            var asyncResult = new SftpDownloadAsyncResult(asyncCallback, state);

            _ = DoDownloadAndSetResult();

            async Task DoDownloadAndSetResult()
            {
                try
                {
                    await InternalDownloadFile(
                        path,
                        output,
                        asyncResult,
                        downloadProgress,
                        isAsync: true,
                        CancellationToken.None).ConfigureAwait(false);

                    asyncResult.SetAsCompleted(exception: null, completedSynchronously: false);
                }
                catch (Exception exp)
                {
                    asyncResult.SetAsCompleted(exp, completedSynchronously: false);
                }
            }

            return asyncResult;
        }










        public void EndDownloadFile(IAsyncResult asyncResult)
        {
            if (asyncResult is not SftpDownloadAsyncResult ar || ar.EndInvokeCalled)
            {
                throw new ArgumentException("Either the IAsyncResult object did not come from the corresponding async method on this type, or EndExecute was called multiple times with the same IAsyncResult.");
            }


            ar.EndInvoke();
        }


        public void UploadFile(Stream input, string path, Action<ulong>? uploadCallback = null)
        {
            UploadFile(input, path, canOverride: true, uploadCallback);
        }


        public void UploadFile(Stream input, string path, bool canOverride, Action<ulong>? uploadCallback = null)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            CheckDisposed();

            var flags = Flags.Write | Flags.Truncate;

            if (canOverride)
            {
                flags |= Flags.CreateNewOrOpen;
            }
            else
            {
                flags |= Flags.CreateNew;
            }

            IProgress<UploadFileProgressReport>? uploadProgress = null;

            if (uploadCallback != null)
            {
                uploadProgress = new ThreadPoolProgress<UploadFileProgressReport>(r => uploadCallback(r.TotalBytesUploaded));
            }

            InternalUploadFile(
                input,
                path,
                flags,
                asyncResult: null,
                uploadProgress,
                isAsync: false,
                CancellationToken.None).GetAwaiter().GetResult();
        }


        public Task UploadFileAsync(Stream input, string path, CancellationToken cancellationToken = default)
        {
            return UploadFileAsync(input, path, canOverride: true, uploadProgress: null, cancellationToken);
        }


        public Task UploadFileAsync(Stream input, string path, IProgress<UploadFileProgressReport>? uploadProgress, CancellationToken cancellationToken = default)
        {
            return UploadFileAsync(input, path, canOverride: true, uploadProgress, cancellationToken);
        }


        public Task UploadFileAsync(Stream input, string path, bool canOverride, IProgress<UploadFileProgressReport>? uploadProgress = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            CheckDisposed();

            var flags = Flags.Write | Flags.Truncate;

            if (canOverride)
            {
                flags |= Flags.CreateNewOrOpen;
            }
            else
            {
                flags |= Flags.CreateNew;
            }

            return InternalUploadFile(
                input,
                path,
                flags,
                asyncResult: null,
                uploadProgress,
                isAsync: true,
                cancellationToken);
        }























        public IAsyncResult BeginUploadFile(Stream input, string path)
        {
            return BeginUploadFile(input, path, canOverride: true, asyncCallback: null, state: null);
        }
























        public IAsyncResult BeginUploadFile(Stream input, string path, AsyncCallback? asyncCallback)
        {
            return BeginUploadFile(input, path, canOverride: true, asyncCallback, state: null);
        }


























        public IAsyncResult BeginUploadFile(Stream input, string path, AsyncCallback? asyncCallback, object? state, Action<ulong>? uploadCallback = null)
        {
            return BeginUploadFile(input, path, canOverride: true, asyncCallback, state, uploadCallback);
        }


























        public IAsyncResult BeginUploadFile(Stream input, string path, bool canOverride, AsyncCallback? asyncCallback, object? state, Action<ulong>? uploadCallback = null)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            CheckDisposed();

            var flags = Flags.Write | Flags.Truncate;

            if (canOverride)
            {
                flags |= Flags.CreateNewOrOpen;
            }
            else
            {
                flags |= Flags.CreateNew;
            }

            IProgress<UploadFileProgressReport>? uploadProgress = null;

            if (uploadCallback != null)
            {




                uploadProgress = new ThreadPoolProgress<UploadFileProgressReport>(r => uploadCallback(r.TotalBytesUploaded));
            }

            var asyncResult = new SftpUploadAsyncResult(asyncCallback, state);

            _ = DoUploadAndSetResult();

            async Task DoUploadAndSetResult()
            {
                try
                {
                    await InternalUploadFile(
                        input,
                        path,
                        flags,
                        asyncResult,
                        uploadProgress,
                        isAsync: true,
                        CancellationToken.None).ConfigureAwait(false);

                    asyncResult.SetAsCompleted(exception: null, completedSynchronously: false);
                }
                catch (Exception exp)
                {
                    asyncResult.SetAsCompleted(exp, completedSynchronously: false);
                }
            }

            return asyncResult;
        }










        public void EndUploadFile(IAsyncResult asyncResult)
        {
            if (asyncResult is not SftpUploadAsyncResult ar || ar.EndInvokeCalled)
            {
                throw new ArgumentException("Either the IAsyncResult object did not come from the corresponding async method on this type, or EndExecute was called multiple times with the same IAsyncResult.");
            }


            ar.EndInvoke();
        }











        public SftpFileSystemInformation GetStatus(string path)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            return _sftpSession.RequestStatVfs(fullPath);
        }













        public async Task<SftpFileSystemInformation> GetStatusAsync(string path, CancellationToken cancellationToken)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);
            return await _sftpSession.RequestStatVfsAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }

        #region File Methods













        public void AppendAllLines(string path, IEnumerable<string> contents)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(contents);

            using (var stream = AppendText(path))
            {
                foreach (var line in contents)
                {
                    stream.WriteLine(line);
                }
            }
        }











        public void AppendAllLines(string path, IEnumerable<string> contents, Encoding encoding)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(contents);

            using (var stream = AppendText(path, encoding))
            {
                foreach (var line in contents)
                {
                    stream.WriteLine(line);
                }
            }
        }













        public void AppendAllText(string path, string contents)
        {
            using (var stream = AppendText(path))
            {
                stream.Write(contents);
            }
        }











        public void AppendAllText(string path, string contents, Encoding encoding)
        {
            using (var stream = AppendText(path, encoding))
            {
                stream.Write(contents);
            }
        }














        public StreamWriter AppendText(string path)
        {
            return AppendText(path, Utf8NoBOM);
        }














        public StreamWriter AppendText(string path, Encoding encoding)
        {
            CheckDisposed();
            ArgumentNullException.ThrowIfNull(encoding);

            return new StreamWriter(Open(path, FileMode.Append, FileAccess.Write), encoding);
        }















        public SftpFileStream Create(string path)
        {
            return Create(path, (int)_bufferSize);
        }
















        public SftpFileStream Create(string path, int bufferSize)
        {
            CheckDisposed();

            return SftpFileStream.Open(_sftpSession, path, FileMode.Create, FileAccess.ReadWrite, bufferSize);
        }


        public StreamWriter CreateText(string path)
        {
            return CreateText(path, Utf8NoBOM);
        }


        public StreamWriter CreateText(string path, Encoding encoding)
        {
            CheckDisposed();

            return new StreamWriter(Open(path, FileMode.Create, FileAccess.Write), encoding);
        }









        public void Delete(string path)
        {
            var file = Get(path);
            file.Delete();
        }


        public async Task DeleteAsync(string path, CancellationToken cancellationToken = default)
        {
            var file = await GetAsync(path, cancellationToken).ConfigureAwait(false);
            await file.DeleteAsync(cancellationToken).ConfigureAwait(false);
        }












        public DateTime GetLastAccessTime(string path)
        {
            var file = Get(path);
            return file.LastAccessTime;
        }












        public DateTime GetLastAccessTimeUtc(string path)
        {
            var lastAccessTime = GetLastAccessTime(path);
            return lastAccessTime.ToUniversalTime();
        }












        public DateTime GetLastWriteTime(string path)
        {
            var file = Get(path);
            return file.LastWriteTime;
        }












        public DateTime GetLastWriteTimeUtc(string path)
        {
            var lastWriteTime = GetLastWriteTime(path);
            return lastWriteTime.ToUniversalTime();
        }












        public SftpFileStream Open(string path, FileMode mode)
        {
            return Open(path, mode, FileAccess.ReadWrite);
        }













        public SftpFileStream Open(string path, FileMode mode, FileAccess access)
        {
            CheckDisposed();

            return SftpFileStream.Open(_sftpSession, path, mode, access, (int)_bufferSize);
        }















        public Task<SftpFileStream> OpenAsync(string path, FileMode mode, FileAccess access, CancellationToken cancellationToken)
        {
            CheckDisposed();

            return SftpFileStream.OpenAsync(_sftpSession, path, mode, access, (int)_bufferSize, cancellationToken);
        }











        public SftpFileStream OpenRead(string path)
        {
            return Open(path, FileMode.Open, FileAccess.Read);
        }











        public StreamReader OpenText(string path)
        {
            return new StreamReader(OpenRead(path), Encoding.UTF8);
        }














        public SftpFileStream OpenWrite(string path)
        {
            return Open(path, FileMode.OpenOrCreate, FileAccess.Write);
        }











        public byte[] ReadAllBytes(string path)
        {
            using (var stream = OpenRead(path))
            {
                byte[] buffer;

                if (stream.CanSeek)
                {
                    buffer = new byte[stream.Length];
                    stream.ReadExactly(buffer, 0, buffer.Length);
                }
                else
                {
                    MemoryStream ms = new();
                    stream.CopyTo(ms);
                    buffer = ms.ToArray();
                }

                return buffer;
            }
        }











        public string[] ReadAllLines(string path)
        {
            return ReadAllLines(path, Encoding.UTF8);
        }












        public string[] ReadAllLines(string path, Encoding encoding)
        {
            return ReadLines(path, encoding).ToArray();
        }











        public string ReadAllText(string path)
        {
            return ReadAllText(path, Encoding.UTF8);
        }












        public string ReadAllText(string path, Encoding encoding)
        {
            using var sr = new StreamReader(OpenRead(path), encoding);
            return sr.ReadToEnd();
        }















        public IEnumerable<string> ReadLines(string path)
        {
            return ReadLines(path, Encoding.UTF8);
        }
















        public IEnumerable<string> ReadLines(string path, Encoding encoding)
        {

            ArgumentNullException.ThrowIfNull(path);






            return Enumerate();

            IEnumerable<string> Enumerate()
            {
                using var sr = new StreamReader(OpenRead(path), encoding);

                string? line;

                while ((line = sr.ReadLine()) != null)
                {
                    yield return line;
                }
            }
        }






        public void SetLastAccessTime(string path, DateTime lastAccessTime)
        {
            var attributes = GetAttributes(path);
            attributes.LastAccessTime = lastAccessTime;
            SetAttributes(path, attributes);
        }






        public void SetLastAccessTimeUtc(string path, DateTime lastAccessTimeUtc)
        {
            var attributes = GetAttributes(path);
            attributes.LastAccessTimeUtc = lastAccessTimeUtc;
            SetAttributes(path, attributes);
        }






        public void SetLastWriteTime(string path, DateTime lastWriteTime)
        {
            var attributes = GetAttributes(path);
            attributes.LastWriteTime = lastWriteTime;
            SetAttributes(path, attributes);
        }






        public void SetLastWriteTimeUtc(string path, DateTime lastWriteTimeUtc)
        {
            var attributes = GetAttributes(path);
            attributes.LastWriteTimeUtc = lastWriteTimeUtc;
            SetAttributes(path, attributes);
        }


        public void WriteAllBytes(string path, byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);

            UploadFile(new MemoryStream(bytes), path);
        }


        public void WriteAllLines(string path, IEnumerable<string> contents)
        {
            WriteAllLines(path, contents, Utf8NoBOM);
        }


        public void WriteAllLines(string path, string[] contents)
        {
            WriteAllLines(path, contents, Utf8NoBOM);
        }


        public void WriteAllLines(string path, IEnumerable<string> contents, Encoding encoding)
        {
            using (var stream = CreateText(path, encoding))
            {
                foreach (var line in contents)
                {
                    stream.WriteLine(line);
                }
            }
        }


        public void WriteAllLines(string path, string[] contents, Encoding encoding)
        {
            WriteAllLines(path, (IEnumerable<string>)contents, encoding);
        }


        public void WriteAllText(string path, string contents)
        {
            using (var stream = CreateText(path))
            {
                stream.Write(contents);
            }
        }


        public void WriteAllText(string path, string contents, Encoding encoding)
        {
            using (var stream = CreateText(path, encoding))
            {
                stream.Write(contents);
            }
        }












        public SftpFileAttributes GetAttributes(string path)
        {
            CheckDisposed();

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            return _sftpSession.RequestLStat(fullPath);
        }














        public async Task<SftpFileAttributes> GetAttributesAsync(string path, CancellationToken cancellationToken)
        {
            CheckDisposed();

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);

            return await _sftpSession.RequestLStatAsync(fullPath, cancellationToken).ConfigureAwait(false);
        }









        public void SetAttributes(string path, SftpFileAttributes fileAttributes)
        {
            CheckDisposed();

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            _sftpSession.RequestSetStat(fullPath, fileAttributes);
        }

        #endregion

        #region SynchronizeDirectories














        public IEnumerable<FileInfo> SynchronizeDirectories(string sourcePath, string destinationPath, string searchPattern)
        {
            ArgumentNullException.ThrowIfNull(sourcePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);

            return InternalSynchronizeDirectories(sourcePath, destinationPath, searchPattern, asyncResult: null);
        }















        public IAsyncResult BeginSynchronizeDirectories(string sourcePath, string destinationPath, string searchPattern, AsyncCallback? asyncCallback, object? state)
        {
            ArgumentNullException.ThrowIfNull(sourcePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
            ArgumentNullException.ThrowIfNull(searchPattern);

            var asyncResult = new SftpSynchronizeDirectoriesAsyncResult(asyncCallback, state);

            ThreadAbstraction.ExecuteThread(() =>
                {
                    try
                    {
                        var result = InternalSynchronizeDirectories(sourcePath, destinationPath, searchPattern, asyncResult);

                        asyncResult.SetAsCompleted(result, completedSynchronously: false);
                    }
                    catch (Exception exp)
                    {
                        asyncResult.SetAsCompleted(exp, completedSynchronously: false);
                    }
                });

            return asyncResult;
        }










        public IEnumerable<FileInfo> EndSynchronizeDirectories(IAsyncResult asyncResult)
        {
            if (asyncResult is not SftpSynchronizeDirectoriesAsyncResult ar || ar.EndInvokeCalled)
            {
                throw new ArgumentException("Either the IAsyncResult object did not come from the corresponding async method on this type, or EndExecute was called multiple times with the same IAsyncResult.");
            }


            return ar.EndInvoke();
        }

        private List<FileInfo> InternalSynchronizeDirectories(string sourcePath, string destinationPath, string searchPattern, SftpSynchronizeDirectoriesAsyncResult? asyncResult)
        {
            if (!Directory.Exists(sourcePath))
            {
                throw new FileNotFoundException(string.Format("Source directory not found: {0}", sourcePath));
            }

            var uploadedFiles = new List<FileInfo>();

            var sourceDirectory = new DirectoryInfo(sourcePath);

            using (var sourceFiles = sourceDirectory.EnumerateFiles(searchPattern).GetEnumerator())
            {
                if (!sourceFiles.MoveNext())
                {
                    return uploadedFiles;
                }

                #region Existing Files at The Destination

                var destFiles = InternalListDirectory(destinationPath, asyncResult: null, listCallback: null);
                var destDict = new Dictionary<string, ISftpFile>();
                foreach (var destFile in destFiles)
                {
                    if (destFile.IsDirectory)
                    {
                        continue;
                    }

                    destDict.Add(destFile.Name, destFile);
                }

                #endregion

                #region Upload the difference

                const Flags uploadFlag = Flags.Write | Flags.Truncate | Flags.CreateNewOrOpen;
                do
                {
                    var localFile = sourceFiles.Current;
                    if (localFile is null)
                    {
                        continue;
                    }

                    var isDifferent = true;
                    if (destDict.TryGetValue(localFile.Name, out var remoteFile))
                    {

                        isDifferent = localFile.Length != remoteFile.Length;
                    }

                    if (isDifferent)
                    {
                        var remoteFileName = string.Format(CultureInfo.InvariantCulture, @"{0}/{1}", destinationPath, localFile.Name);
                        try
                        {
                            using (var file = File.OpenRead(localFile.FullName))
                            {
#pragma warning disable CA2025
                                InternalUploadFile(
                                    file,
                                    remoteFileName,
                                    uploadFlag,
                                    asyncResult: null,
                                    uploadProgress: null,
                                    isAsync: false,
                                    CancellationToken.None).GetAwaiter().GetResult();
#pragma warning restore CA2025
                            }

                            uploadedFiles.Add(localFile);

                            asyncResult?.Update(uploadedFiles.Count);
                        }
                        catch (Exception ex)
                        {
                            throw new SshException($"Failed to upload {localFile.FullName} to {remoteFileName}", ex);
                        }
                    }
                }
                while (sourceFiles.MoveNext());
            }

            #endregion

            return uploadedFiles;
        }

        #endregion












        private List<ISftpFile> InternalListDirectory(string path, SftpListDirectoryAsyncResult? asyncResult, Action<int>? listCallback)
        {
            ArgumentNullException.ThrowIfNull(path);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var fullPath = _sftpSession.GetCanonicalPath(path);

            var handle = _sftpSession.RequestOpenDir(fullPath);

            var basePath = fullPath;

#if NET
            if (!basePath.EndsWith('/'))
#else
            if (!basePath.EndsWith("/", StringComparison.Ordinal))
#endif
            {
                basePath = string.Format("{0}/", fullPath);
            }

            var result = new List<ISftpFile>();

            var files = _sftpSession.RequestReadDir(handle);

            while (files is not null)
            {
                foreach (var f in files)
                {
                    result.Add(new SftpFile(_sftpSession,
                                            string.Format(CultureInfo.InvariantCulture, "{0}{1}", basePath, f.Key),
                                            f.Value));
                }

                asyncResult?.Update(result.Count);


                if (listCallback is not null)
                {

                    ThreadAbstraction.ExecuteThread(() => listCallback(result.Count));
                }

                files = _sftpSession.RequestReadDir(handle);
            }

            _sftpSession.RequestClose(handle);

            return result;
        }

#pragma warning disable CA1849
        private async Task InternalDownloadFile(
            string path,
            Stream output,
            SftpDownloadAsyncResult? asyncResult,
            IProgress<DownloadFileProgressReport>? downloadProgress,
            bool isAsync,
            CancellationToken cancellationToken)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(path));
            Debug.Assert(output is not null);
            Debug.Assert(isAsync || cancellationToken == default);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            SftpFileStream sftpStream;

            if (isAsync)
            {
                var fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);

                sftpStream = await SftpFileStream.OpenAsync(
                    _sftpSession,
                    fullPath,
                    FileMode.Open,
                    FileAccess.Read,
                    (int)_bufferSize,
                    cancellationToken,
                    isDownloadFile: true).ConfigureAwait(false);
            }
            else
            {
                var fullPath = _sftpSession.GetCanonicalPath(path);

                sftpStream = SftpFileStream.Open(
                    _sftpSession,
                    fullPath,
                    FileMode.Open,
                    FileAccess.Read,
                    (int)_bufferSize,
                    isDownloadFile: true);
            }




            var buffer = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                ulong totalBytesRead = 0;
                while (true)
                {

                    if (asyncResult is not null && asyncResult.IsDownloadCanceled)
                    {
                        break;
                    }

                    var bytesRead = isAsync
#if NET
                        ? await sftpStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)
#else
                        ? await sftpStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)
#endif
                        : sftpStream.Read(buffer, 0, buffer.Length);

                    if (bytesRead == 0)
                    {
                        break;
                    }

                    if (isAsync)
                    {
#if NET
                        await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
#else
                        await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
#endif
                    }
                    else
                    {
                        output.Write(buffer, 0, bytesRead);
                    }

                    totalBytesRead += (ulong)bytesRead;

                    asyncResult?.Update(totalBytesRead);

                    downloadProgress?.Report(new DownloadFileProgressReport()
                    {
                        TotalBytesDownloaded = totalBytesRead
                    });
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);

                if (isAsync)
                {
                    await sftpStream.DisposeAsync().ConfigureAwait(false);
                }
                else
                {
                    sftpStream.Dispose();
                }
            }
        }

        private async Task InternalUploadFile(
            Stream input,
            string path,
            Flags flags,
            SftpUploadAsyncResult? asyncResult,
            IProgress<UploadFileProgressReport>? uploadProgress,
            bool isAsync,
            CancellationToken cancellationToken)
        {
            Debug.Assert(isAsync || cancellationToken == default);

            if (_sftpSession is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            string fullPath;
            byte[] handle;

            if (isAsync)
            {
                fullPath = await _sftpSession.GetCanonicalPathAsync(path, cancellationToken).ConfigureAwait(false);
                handle = await _sftpSession.RequestOpenAsync(fullPath, flags, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                fullPath = _sftpSession.GetCanonicalPath(path);
                handle = _sftpSession.RequestOpen(fullPath, flags);
            }

            ulong offset = 0;


            var dataCapacity = (int)_sftpSession.CalculateOptimalWriteLength(_bufferSize, handle);

            using var buffer = new SftpWriteRequestBuffer(handle, dataCapacity, usePool: true);

            var dataBuffer = buffer.Data;

            Debug.Assert(dataBuffer.Count >= dataCapacity);

            var expectedResponses = 0;




            using var mres = new ManualResetEventSlim(initialState: false);

            ExceptionDispatchInfo? exception = null;

            while (true)
            {
                var bytesRead = isAsync
#if NET
                    ? await input.ReadAsync(dataBuffer.AsMemory(0, dataCapacity), cancellationToken).ConfigureAwait(false)
#else
                    ? await input.ReadAsync(dataBuffer.Array, dataBuffer.Offset, dataCapacity, cancellationToken).ConfigureAwait(false)
#endif
                    : input.Read(dataBuffer.Array!, dataBuffer.Offset, dataCapacity);

                if (bytesRead == 0)
                {
                    break;
                }

                if (asyncResult is not null && asyncResult.IsUploadCanceled)
                {
                    break;
                }

                exception?.Throw();

                buffer.ServerFileOffset = offset;
                buffer.DataLength = bytesRead;

                var writtenBytes = offset + (ulong)bytesRead;

                _ = Interlocked.Increment(ref expectedResponses);
                mres.Reset();

                _sftpSession.RequestWrite(buffer, s =>
                {
                    var setHandle = false;

                    try
                    {
                        if (Sftp.SftpSession.GetSftpException(s) is Exception ex)
                        {
                            exception = ExceptionDispatchInfo.Capture(ex);
                        }

                        if (exception is not null)
                        {
                            setHandle = true;
                            return;
                        }

                        Debug.Assert(s.StatusCode == StatusCode.Ok);

                        asyncResult?.Update(writtenBytes);

                        uploadProgress?.Report(new UploadFileProgressReport()
                        {
                            TotalBytesUploaded = writtenBytes
                        });
                    }
                    finally
                    {
                        if (Interlocked.Decrement(ref expectedResponses) == 0 || setHandle)
                        {
                            mres.Set();
                        }
                    }
                });

                offset += (ulong)bytesRead;
            }





            if (Volatile.Read(ref expectedResponses) != 0)
            {
                if (isAsync)
                {
                    await _sftpSession.WaitOnHandleAsync(mres.WaitHandle, _operationTimeout, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    _sftpSession.WaitOnHandle(mres.WaitHandle, _operationTimeout);
                }
            }

            exception?.Throw();

            if (isAsync)
            {
                await _sftpSession.RequestCloseAsync(handle, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                _sftpSession.RequestClose(handle);
            }
        }
#pragma warning restore CA1849




        protected override void OnConnected()
        {
            base.OnConnected();

            _sftpSession?.Dispose();
            _sftpSession = CreateAndConnectToSftpSession();
        }




        protected override void OnDisconnecting()
        {
            base.OnDisconnecting();



            var sftpSession = _sftpSession;
            if (sftpSession is not null)
            {
                _sftpSession = null;
                sftpSession.Dispose();
            }
        }





        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                var sftpSession = _sftpSession;
                if (sftpSession is not null)
                {
                    _sftpSession = null;
                    sftpSession.Dispose();
                }
            }
        }

        private ISftpSession CreateAndConnectToSftpSession()
        {
            var sftpSession = ServiceFactory.CreateSftpSession(Session,
                                                               _operationTimeout,
                                                               ConnectionInfo.Encoding,
                                                               ServiceFactory.CreateSftpResponseFactory());
            try
            {
                sftpSession.Connect();
                return sftpSession;
            }
            catch
            {
                sftpSession.Dispose();
                throw;
            }
        }




        private sealed class ThreadPoolProgress<T> : IProgress<T>
        {
            private readonly Action<T> _handler;

            public ThreadPoolProgress(Action<T> handler)
            {
                Debug.Assert(handler != null);
                _handler = handler!;
            }

            void IProgress<T>.Report(T value)
            {
                _ = ThreadPool.QueueUserWorkItem(static state =>
                {
                    var (handler, value) = ((Action<T>, T))state!;
                    handler(value);
                },
                (_handler, value));
            }
        }
    }
}
