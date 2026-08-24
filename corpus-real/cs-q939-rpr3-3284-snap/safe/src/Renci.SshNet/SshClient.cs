#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

using Renci.SshNet.Common;

namespace Renci.SshNet
{

    public class SshClient : BaseClient, ISshClient
    {



        private readonly List<ForwardedPort> _forwardedPorts;







        private bool _isDisposed;

        private MemoryStream? _inputStream;


        public IEnumerable<ForwardedPort> ForwardedPorts
        {
            get
            {
                return _forwardedPorts.AsReadOnly();
            }
        }






        public SshClient(ConnectionInfo connectionInfo)
            : this(connectionInfo, ownsConnectionInfo: false)
        {
        }











        public SshClient(string host, int port, string username, string password)
            : this(new PasswordConnectionInfo(host, port, username, password), ownsConnectionInfo: true)
        {
        }









        public SshClient(string host, string username, string password)
            : this(host, ConnectionInfo.DefaultPort, username, password)
        {
        }











        public SshClient(string host, int port, string username, params IPrivateKeySource[] keyFiles)
            : this(new PrivateKeyConnectionInfo(host, port, username, keyFiles), ownsConnectionInfo: true)
        {
        }









        public SshClient(string host, string username, params IPrivateKeySource[] keyFiles)
            : this(host, ConnectionInfo.DefaultPort, username, keyFiles)
        {
        }











        private SshClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo)
            : this(connectionInfo, ownsConnectionInfo, new ServiceFactory())
        {
        }













        internal SshClient(ConnectionInfo connectionInfo, bool ownsConnectionInfo, IServiceFactory serviceFactory)
            : base(connectionInfo, ownsConnectionInfo, serviceFactory)
        {
            _forwardedPorts = new List<ForwardedPort>();
        }




        protected override void OnDisconnecting()
        {
            base.OnDisconnecting();

            foreach (var port in _forwardedPorts)
            {
                port.Stop();
            }
        }


        public void AddForwardedPort(ForwardedPort port)
        {
            ArgumentNullException.ThrowIfNull(port);

            EnsureSessionIsOpen();

            AttachForwardedPort(port);
            _forwardedPorts.Add(port);
        }


        public void RemoveForwardedPort(ForwardedPort port)
        {
            ArgumentNullException.ThrowIfNull(port);


            port.Stop();

            DetachForwardedPort(port);
            _ = _forwardedPorts.Remove(port);
        }

        private void AttachForwardedPort(ForwardedPort port)
        {
            if (port.Session != null && port.Session != Session)
            {
                throw new InvalidOperationException("Forwarded port is already added to a different client.");
            }

            port.Session = Session;
        }

        private static void DetachForwardedPort(ForwardedPort port)
        {
            port.Session = null;
        }


        public SshCommand CreateCommand(string commandText)
        {
            return CreateCommand(commandText, ConnectionInfo.Encoding);
        }


        public SshCommand CreateCommand(string commandText, Encoding encoding)
        {
            EnsureSessionIsOpen();

            ConnectionInfo.Encoding = encoding;
            return new SshCommand(Session!, commandText, encoding);
        }


        public SshCommand RunCommand(string commandText)
        {
            var cmd = CreateCommand(commandText);
            _ = cmd.Execute();
            return cmd;
        }


        public Shell CreateShell(Stream input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint>? terminalModes, int bufferSize)
        {
            EnsureSessionIsOpen();

            return new Shell(Session, input, output, extendedOutput, terminalName, columns, rows, width, height, terminalModes, bufferSize);
        }


        public Shell CreateShell(Stream input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint> terminalModes)
        {
            return CreateShell(input, output, extendedOutput, terminalName, columns, rows, width, height, terminalModes, 1024);
        }


        public Shell CreateShell(Stream input, Stream output, Stream extendedOutput)
        {
            return CreateShell(input, output, extendedOutput, string.Empty, 0, 0, 0, 0, terminalModes: null, 1024);
        }


        public Shell CreateShell(Encoding encoding, string input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint>? terminalModes, int bufferSize)
        {




            _inputStream = new MemoryStream();

            using (var writer = new StreamWriter(_inputStream, encoding, bufferSize: 1024, leaveOpen: true))
            {
                writer.Write(input);
                writer.Flush();
            }

            _ = _inputStream.Seek(0, SeekOrigin.Begin);

            return CreateShell(_inputStream, output, extendedOutput, terminalName, columns, rows, width, height, terminalModes, bufferSize);
        }


        public Shell CreateShell(Encoding encoding, string input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint> terminalModes)
        {
            return CreateShell(encoding, input, output, extendedOutput, terminalName, columns, rows, width, height, terminalModes, 1024);
        }


        public Shell CreateShell(Encoding encoding, string input, Stream output, Stream extendedOutput)
        {
            return CreateShell(encoding, input, output, extendedOutput, string.Empty, 0, 0, 0, 0, terminalModes: null, 1024);
        }


        public Shell CreateShellNoTerminal(Stream input, Stream output, Stream extendedOutput, int bufferSize = -1)
        {
            EnsureSessionIsOpen();

            return new Shell(Session, input, output, extendedOutput, bufferSize);
        }


        public ShellStream CreateShellStream(string terminalName, uint columns, uint rows, uint width, uint height, int bufferSize)
        {
            return CreateShellStream(terminalName, columns, rows, width, height, bufferSize, terminalModeValues: null);
        }


        public ShellStream CreateShellStream(string terminalName, uint columns, uint rows, uint width, uint height, int bufferSize, IDictionary<TerminalModes, uint>? terminalModeValues)
        {
            EnsureSessionIsOpen();

            return ServiceFactory.CreateShellStream(Session, terminalName, columns, rows, width, height, terminalModeValues, bufferSize);
        }


        public ShellStream CreateShellStreamNoTerminal(int bufferSize = -1)
        {
            EnsureSessionIsOpen();

            return ServiceFactory.CreateShellStreamNoTerminal(Session, bufferSize);
        }




        protected override void OnDisconnected()
        {
            base.OnDisconnected();

            for (var i = _forwardedPorts.Count - 1; i >= 0; i--)
            {
                var port = _forwardedPorts[i];
                DetachForwardedPort(port);
                _forwardedPorts.RemoveAt(i);
            }
        }





        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_isDisposed)
            {
                return;
            }

            if (disposing)
            {
                _inputStream?.Dispose();
                _inputStream = null;

                _isDisposed = true;
            }
        }

        private void EnsureSessionIsOpen()
        {
            if (Session is null)
            {
                throw new SshConnectionException("Client not connected.");
            }
        }
    }
}
