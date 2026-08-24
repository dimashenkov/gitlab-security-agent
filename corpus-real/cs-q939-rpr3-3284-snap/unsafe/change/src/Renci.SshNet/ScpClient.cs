#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;

using Renci.SshNet.Channels;
using Renci.SshNet.Common;

namespace Renci.SshNet
{










































#pragma warning disable MA0204
    public partial class ScpClient : BaseClient
    {
        private const string ConstructorObsoleteMessage =
           @"SCP with insufficiently-escaped paths can allow remote command injection. Use a constructor " +
            "taking an IRemotePathTransformation which suits the escaping rules of the remote server and " +
            "the trust environment in which this code runs, and consider using SFTP where possible.";

        private const string FileInfoPattern = @"C(?<mode>\d{4}) (?<length>\d+) (?<filename>.+)";
        private const string DirectoryInfoPattern = @"D(?<mode>\d{4}) (?<length>\d+) (?<filename>.+)";
        private const string TimestampPattern = @"T(?<mtime>\d+) 0 (?<atime>\d+) 0";

#if NET
        private static readonly Regex FileInfoRegex = GetFileInfoRegex();
        private static readonly Regex DirectoryInfoRegex = GetDirectoryInfoRegex();
        private static readonly Regex TimestampRegex = GetTimestampRegex();

        [GeneratedRegex(FileInfoPattern)]
        private static partial Regex GetFileInfoRegex();

        [GeneratedRegex(DirectoryInfoPattern)]
        private static partial Regex GetDirectoryInfoRegex();

        [GeneratedRegex(TimestampPattern)]
        private static partial Regex GetTimestampRegex();
#else
        private static readonly Regex FileInfoRegex = new Regex(FileInfoPattern, RegexOptions.Compiled);
        private static readonly Regex DirectoryInfoRegex = new Regex(DirectoryInfoPattern, RegexOptions.Compiled);
        private static readonly Regex TimestampRegex = new Regex(TimestampPattern, RegexOptions.Compiled);
#endif

        private static readonly byte[] SuccessConfirmationCode = { 0 };
        private static readonly byte[] ErrorConfirmationCode = { 1 };

        private IRemotePathTransformation _remotePathTransformation;
        private TimeSpan _operationTimeout;








        public TimeSpan OperationTimeout
        {
            get
            {
                return _operationTimeout;
            }
            set
            {
                value.EnsureValidTimeout(nameof(OperationTimeout));

                _operationTimeout = value;
            }
        }







        public uint BufferSize { get; set; }




















        public IRemotePathTransformation RemotePathTransformation
        {
            get
            {
                return _remotePathTransformation;
            }
            set
            {
                ArgumentNullException.ThrowIfNull(value);

                _remotePathTransformation = value;
            }
        }

        private static IRemotePathTransformation DefaultTransform
        {
            get
            {
                return SshNet.RemotePathTransformation.DoubleQuote;
            }
        }










        public bool UseDirectoryFlag { get; set; } = true;

        private string EnsureIsDirectoryArg
        {
            get
            {
                return UseDirectoryFlag ? "-d" : string.Empty;
            }
        }




        public event EventHandler<ScpDownloadEventArgs>? Downloading;




        public event EventHandler<ScpUploadEventArgs>? Uploading;







        public ScpClient(ConnectionInfo connectionInfo, IRemotePathTransformation remotePathTransformation)
            : this(connectionInfo, ownsConnectionInfo: false, remotePathTransformation)
        {
        }












        public ScpClient(string host, int port, string username, string password, IRemotePathTransformation remotePathTransformation)
            : this(new PasswordConnectionInfo(host, port, username, password), ownsConnectionInfo: true, remotePathTransformation)
        {
        }










        public ScpClient(string host, string username, string password, IRemotePathTransformation remotePathTransformation)
            : this(host, ConnectionInfo.DefaultPort, username, password, remotePathTransformation)
        {
        }












        public ScpClient(string host, int port, string username, IRemotePathTransformation remotePathTransformation, params IPrivateKeySource[] keyFiles)
            : this(new PrivateKeyConnectionInfo(host, port, username, keyFiles), ownsConnectionInfo: true, remotePathTransformation)
        {
        }










        public ScpClient(string host, string username, IRemotePathTransformation remotePathTransformation, params IPrivateKeySource[] keyFiles)
            : this(host, ConnectionInfo.DefaultPort, username, remotePathTransformation, keyFiles)
        {
        }


        [Obsolete(ConstructorObsoleteMessage)]
        public ScpClient(ConnectionInfo connectionInfo)
            : this(connectionInfo, ownsConnectionInfo: false, DefaultTransform)
        {
        }


        [Obsolete(ConstructorObsoleteMessage)]
        public ScpClient(string host, int port, string username, string password)
            : this(new PasswordConnectionInfo(host, port, username, password), ownsConnectionInfo: true, DefaultTransform)
        {
        }


        [Obsolete(ConstructorObsoleteMessage)]
        public ScpClient(string host, string username, string password)
            : this(host, ConnectionInfo.DefaultPort, username, password, DefaultTransform)
        {
        }


        [Obsolete(ConstructorObsoleteMessage)]
        public ScpClient(string host, int port, string username, params IPrivateKeySource[] keyFiles)
            : this(new PrivateKeyConnectionInfo(host, port, username, keyFiles), ownsConnectionInfo: true, DefaultTransform)
        {
        }


        [Obsolete(ConstructorObsoleteMessage)]
        public ScpClient(string host, string username, params IPrivateKeySource[] keyFiles)
            : this(host, ConnectionInfo.DefaultPort, username, DefaultTransform, keyFiles)
        {
        }












        private ScpClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo, IRemotePathTransformation remotePathTransformation)
            : this(connectionInfo, ownsConnectionInfo, new ServiceFactory(), remotePathTransformation)
        {
        }














        internal ScpClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo, IServiceFactory serviceFactory, IRemotePathTransformation remotePathTransformation)
            : base(connectionInfo, ownsConnectionInfo, serviceFactory)
        {
            OperationTimeout = Timeout.InfiniteTimeSpan;
            BufferSize = 1024 * 16;
            _remotePathTransformation = remotePathTransformation;
        }











        public void Upload(Stream source, string path)
        {
            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var posixPath = PosixPath.CreateAbsoluteOrRelativeFilePath(path);

            using (var input = ServiceFactory.CreatePipeStream())
            using (var channel = Session.CreateChannelSession())
            {
                channel.DataReceived += (sender, e) => input.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
                channel.Closed += (sender, e) => input.Dispose();
                channel.Open();



                if (!channel.SendExecRequest($"scp -t {EnsureIsDirectoryArg} {_remotePathTransformation.Transform(posixPath.Directory)}"))
                {
                    throw SecureExecutionRequestRejectedException();
                }

                CheckReturnCode(input);

                UploadFileModeAndName(channel, input, source.Length, posixPath.File);
                UploadFileContent(channel, input, source, posixPath.File);
            }
        }












        public void Upload(FileInfo fileInfo, string path)
        {
            ArgumentNullException.ThrowIfNull(fileInfo);

            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            var posixPath = PosixPath.CreateAbsoluteOrRelativeFilePath(path);

            using (var input = ServiceFactory.CreatePipeStream())
            using (var channel = Session.CreateChannelSession())
            {
                channel.DataReceived += (sender, e) => input.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
                channel.Closed += (sender, e) => input.Dispose();
                channel.Open();



                if (!channel.SendExecRequest($"scp -t {EnsureIsDirectoryArg} {_remotePathTransformation.Transform(posixPath.Directory)}"))
                {
                    throw SecureExecutionRequestRejectedException();
                }

                CheckReturnCode(input);

                using (var source = fileInfo.OpenRead())
                {
                    UploadTimes(channel, input, fileInfo);
                    UploadFileModeAndName(channel, input, source.Length, posixPath.File);
                    UploadFileContent(channel, input, source, fileInfo.Name);
                }
            }
        }












        public void Upload(DirectoryInfo directoryInfo, string path)
        {
            ArgumentNullException.ThrowIfNull(directoryInfo);
            ArgumentException.ThrowIfNullOrEmpty(path);

            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            using (var input = ServiceFactory.CreatePipeStream())
            using (var channel = Session.CreateChannelSession())
            {
                channel.DataReceived += (sender, e) => input.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
                channel.Closed += (sender, e) => input.Dispose();
                channel.Open();






                if (!channel.SendExecRequest($"scp -r -p {EnsureIsDirectoryArg} -t {_remotePathTransformation.Transform(path)}"))
                {
                    throw SecureExecutionRequestRejectedException();
                }

                CheckReturnCode(input);

                UploadDirectoryContent(channel, input, directoryInfo);
            }
        }











        public void Download(string filename, FileInfo fileInfo)
        {
            ArgumentException.ThrowIfNullOrEmpty(filename);
            ArgumentNullException.ThrowIfNull(fileInfo);

            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            using (var input = ServiceFactory.CreatePipeStream())
            using (var channel = Session.CreateChannelSession())
            {
                channel.DataReceived += (sender, e) => input.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
                channel.Closed += (sender, e) => input.Dispose();
                channel.Open();


                if (!channel.SendExecRequest($"scp -pf {_remotePathTransformation.Transform(filename)}"))
                {
                    throw SecureExecutionRequestRejectedException();
                }


                SendSuccessConfirmation(channel);

                InternalDownload(channel, input, fileInfo);
            }
        }











        public void Download(string directoryName, DirectoryInfo directoryInfo)
        {
            ArgumentException.ThrowIfNullOrEmpty(directoryName);
            ArgumentNullException.ThrowIfNull(directoryInfo);

            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            using (var input = ServiceFactory.CreatePipeStream())
            using (var channel = Session.CreateChannelSession())
            {
                channel.DataReceived += (sender, e) => input.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
                channel.Closed += (sender, e) => input.Dispose();
                channel.Open();


                if (!channel.SendExecRequest($"scp -prf {_remotePathTransformation.Transform(directoryName)}"))
                {
                    throw SecureExecutionRequestRejectedException();
                }


                SendSuccessConfirmation(channel);

                InternalDownload(channel, input, directoryInfo);
            }
        }











        public void Download(string filename, Stream destination)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(filename);
            ArgumentNullException.ThrowIfNull(destination);

            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }

            using (var input = ServiceFactory.CreatePipeStream())
            using (var channel = Session.CreateChannelSession())
            {
                channel.DataReceived += (sender, e) => input.Write(e.Data.Array!, e.Data.Offset, e.Data.Count);
                channel.Closed += (sender, e) => input.Dispose();
                channel.Open();


                if (!channel.SendExecRequest(string.Concat("scp -f ", _remotePathTransformation.Transform(filename))))
                {
                    throw SecureExecutionRequestRejectedException();
                }

                SendSuccessConfirmation(channel);

                var message = ReadString(input);
                var match = FileInfoRegex.Match(message);

                if (match.Success)
                {

                    SendSuccessConfirmation(channel);

                    var length = long.Parse(match.Result("${length}"), CultureInfo.InvariantCulture);
                    var fileName = match.Result("${filename}");

                    InternalDownload(channel, input, destination, fileName, length);
                }
                else
                {
                    SendErrorConfirmation(channel, string.Format("\"{0}\" is not valid protocol message.", message));
                }
            }
        }

        private static void SendData(IChannel channel, byte[] buffer, int length)
        {
            channel.SendData(buffer, 0, length);
        }

        private static void SendData(IChannel channel, byte[] buffer)
        {
            channel.SendData(buffer);
        }

        private static int ReadByte(Stream stream)
        {
            var b = stream.ReadByte();

            if (b == -1)
            {
                throw new SshException("Stream has been closed.");
            }

            return b;
        }

        private static SshException SecureExecutionRequestRejectedException()
        {
            throw new SshException("Secure copy execution request was rejected by the server. Please consult the server logs.");
        }
















        private void UploadFileModeAndName(IChannelSession channel, Stream input, long fileSize, string serverFileName)
        {
            SendData(channel, string.Format("C0644 {0} {1}\n", fileSize, serverFileName));
            CheckReturnCode(input);
        }











        private void UploadFileContent(IChannelSession channel, Stream input, Stream source, string remoteFileName)
        {
            var totalLength = source.Length;
            var buffer = new byte[BufferSize];

            var read = source.Read(buffer, 0, buffer.Length);

            long totalRead = 0;

            while (read > 0)
            {
                SendData(channel, buffer, read);

                totalRead += read;

                RaiseUploadingEvent(remoteFileName, totalLength, totalRead);

                read = source.Read(buffer, 0, buffer.Length);
            }

            if (totalLength == 0 && totalRead == 0)
            {
                RaiseUploadingEvent(remoteFileName, totalLength, totalRead);
            }

            SendSuccessConfirmation(channel);
            CheckReturnCode(input);
        }

        private void RaiseDownloadingEvent(string filename, long size, long downloaded)
        {
            Downloading?.Invoke(this, new ScpDownloadEventArgs(filename, size, downloaded));
        }

        private void RaiseUploadingEvent(string filename, long size, long uploaded)
        {
            Uploading?.Invoke(this, new ScpUploadEventArgs(filename, size, uploaded));
        }

        private static void SendSuccessConfirmation(IChannel channel)
        {
            SendData(channel, SuccessConfirmationCode);
        }

        private void SendErrorConfirmation(IChannel channel, string message)
        {
            SendData(channel, ErrorConfirmationCode);
            SendData(channel, string.Concat(message, "\n"));
        }





        private void CheckReturnCode(Stream input)
        {
            var b = ReadByte(input);

            if (b > 0)
            {
                var errorText = ReadString(input);

                throw new ScpException(errorText);
            }
        }

        private void SendData(IChannel channel, string command)
        {
            channel.SendData(ConnectionInfo.Encoding.GetBytes(command));
        }








        private string ReadString(Stream stream)
        {
            var hasError = false;

            var buffer = new List<byte>();

            var b = ReadByte(stream);
            if (b is 1 or 2)
            {
                hasError = true;
                b = ReadByte(stream);
            }

            while (b != SshNet.Session.LineFeed)
            {
                buffer.Add((byte)b);
                b = ReadByte(stream);
            }

            var readBytes = buffer.ToArray();

            if (hasError)
            {
                throw new ScpException(ConnectionInfo.Encoding.GetString(readBytes, 0, readBytes.Length));
            }

            return ConnectionInfo.Encoding.GetString(readBytes, 0, readBytes.Length);
        }








        private void UploadTimes(IChannelSession channel, Stream input, FileSystemInfo fileOrDirectory)
        {
            var zeroTime = DateTime.UnixEpoch;
            var modificationSeconds = (long)(fileOrDirectory.LastWriteTimeUtc - zeroTime).TotalSeconds;
            var accessSeconds = (long)(fileOrDirectory.LastAccessTimeUtc - zeroTime).TotalSeconds;
            SendData(channel, string.Format(CultureInfo.InvariantCulture, "T{0} 0 {1} 0\n", modificationSeconds, accessSeconds));
            CheckReturnCode(input);
        }







        private void UploadDirectoryContent(IChannelSession channel, Stream input, DirectoryInfo directoryInfo)
        {

            var files = directoryInfo.GetFiles();
            foreach (var file in files)
            {
                using (var source = file.OpenRead())
                {
                    UploadTimes(channel, input, file);
                    UploadFileModeAndName(channel, input, source.Length, file.Name);
                    UploadFileContent(channel, input, source, file.Name);
                }
            }


            var directories = directoryInfo.GetDirectories();
            foreach (var directory in directories)
            {
                UploadTimes(channel, input, directory);
                UploadDirectoryModeAndName(channel, input, directory.Name);
                UploadDirectoryContent(channel, input, directory);
            }


            SendData(channel, "E\n");
            CheckReturnCode(input);
        }




        private void UploadDirectoryModeAndName(IChannelSession channel, Stream input, string directoryName)
        {
            SendData(channel, string.Format("D0755 0 {0}\n", directoryName));
            CheckReturnCode(input);
        }

        private void InternalDownload(IChannel channel, Stream input, Stream output, string filename, long length)
        {
            var buffer = new byte[Math.Min(length, BufferSize)];
            var needToRead = length;

            do
            {
                var read = input.Read(buffer, 0, (int)Math.Min(needToRead, BufferSize));

                output.Write(buffer, 0, read);

                RaiseDownloadingEvent(filename, length, length - needToRead);

                needToRead -= read;
            }
            while (needToRead > 0);

            output.Flush();


            RaiseDownloadingEvent(filename, length, length - needToRead);


            SendSuccessConfirmation(channel);

            CheckReturnCode(input);
        }

        private void InternalDownload(IChannelSession channel, Stream input, FileSystemInfo fileSystemInfo)
        {
            var modifiedTime = DateTime.Now;
            var accessedTime = DateTime.Now;

            var startDirectoryFullName = fileSystemInfo.FullName;
            var currentDirectoryFullName = startDirectoryFullName;
            var directoryCounter = 0;

            while (true)
            {
                var message = ReadString(input);

                if (message == "E")
                {
                    SendSuccessConfirmation(channel);

                    directoryCounter--;

                    if (directoryCounter == 0)
                    {
                        break;
                    }

                    var currentDirectoryParent = new DirectoryInfo(currentDirectoryFullName).Parent;

                    Debug.Assert(currentDirectoryParent is not null, $"Should be {directoryCounter.ToString(CultureInfo.InvariantCulture)} levels deeper than {startDirectoryFullName}.");

                    currentDirectoryFullName = currentDirectoryParent.FullName;

                    continue;
                }

                var match = DirectoryInfoRegex.Match(message);
                if (match.Success)
                {
                    SendSuccessConfirmation(channel);


                    var filename = match.Result("${filename}");

                    DirectoryInfo newDirectoryInfo;
                    if (directoryCounter > 0)
                    {
                        newDirectoryInfo = Directory.CreateDirectory(Path.Combine(currentDirectoryFullName, filename));
                        newDirectoryInfo.LastAccessTime = accessedTime;
                        newDirectoryInfo.LastWriteTime = modifiedTime;
                    }
                    else
                    {

                        newDirectoryInfo = (DirectoryInfo)fileSystemInfo;
                    }

                    directoryCounter++;

                    currentDirectoryFullName = newDirectoryInfo.FullName;
                    continue;
                }

                match = FileInfoRegex.Match(message);
                if (match.Success)
                {

                    SendSuccessConfirmation(channel);

                    var length = long.Parse(match.Result("${length}"), CultureInfo.InvariantCulture);
                    var fileName = match.Result("${filename}");

                    if (fileSystemInfo is not FileInfo fileInfo)
                    {
                        fileInfo = new FileInfo(Path.Combine(currentDirectoryFullName, fileName));
                    }

                    using (var output = fileInfo.Open(FileMode.Create, FileAccess.Write))
                    {
                        InternalDownload(channel, input, output, fileName, length);
                    }

                    fileInfo.LastAccessTime = accessedTime;
                    fileInfo.LastWriteTime = modifiedTime;

                    if (directoryCounter == 0)
                    {
                        break;
                    }

                    continue;
                }

                match = TimestampRegex.Match(message);
                if (match.Success)
                {

                    SendSuccessConfirmation(channel);

                    var mtime = long.Parse(match.Result("${mtime}"), CultureInfo.InvariantCulture);
                    var atime = long.Parse(match.Result("${atime}"), CultureInfo.InvariantCulture);

                    var zeroTime = DateTime.UnixEpoch;
                    modifiedTime = zeroTime.AddSeconds(mtime);
                    accessedTime = zeroTime.AddSeconds(atime);
                    continue;
                }

                SendErrorConfirmation(channel, string.Format("\"{0}\" is not valid protocol message.", message));
            }
        }
    }
}
