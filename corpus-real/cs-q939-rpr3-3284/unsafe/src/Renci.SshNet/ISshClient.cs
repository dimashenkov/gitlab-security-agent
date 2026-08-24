#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Renci.SshNet.Common;

namespace Renci.SshNet
{



    public interface ISshClient : IBaseClient
    {



        IEnumerable<ForwardedPort> ForwardedPorts { get; }








        public void AddForwardedPort(ForwardedPort port);






        public void RemoveForwardedPort(ForwardedPort port);







        public SshCommand CreateCommand(string commandText);










        public SshCommand CreateCommand(string commandText, Encoding encoding);












        public SshCommand RunCommand(string commandText);


















        public Shell CreateShell(Stream input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint>? terminalModes, int bufferSize);

















        public Shell CreateShell(Stream input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint> terminalModes);











        public Shell CreateShell(Stream input, Stream output, Stream extendedOutput);



















        public Shell CreateShell(Encoding encoding, string input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint>? terminalModes, int bufferSize);


















        public Shell CreateShell(Encoding encoding, string input, Stream output, Stream extendedOutput, string terminalName, uint columns, uint rows, uint width, uint height, IDictionary<TerminalModes, uint> terminalModes);












        public Shell CreateShell(Encoding encoding, string input, Stream output, Stream extendedOutput);













        public Shell CreateShellNoTerminal(Stream input, Stream output, Stream extendedOutput, int bufferSize = -1);
























        public ShellStream CreateShellStream(string terminalName, uint columns, uint rows, uint width, uint height, int bufferSize);

























        public ShellStream CreateShellStream(string terminalName, uint columns, uint rows, uint width, uint height, int bufferSize, IDictionary<TerminalModes, uint>? terminalModeValues);










        public ShellStream CreateShellStreamNoTerminal(int bufferSize = -1);
    }
}
