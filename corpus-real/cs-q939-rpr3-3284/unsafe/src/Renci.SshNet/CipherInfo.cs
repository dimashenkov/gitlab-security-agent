using System;

using Renci.SshNet.Common;
using Renci.SshNet.Security.Cryptography;

namespace Renci.SshNet
{



    public class CipherInfo
    {






        public int KeySize { get; private set; }







        public bool IsAead { get; private set; }




        public Func<byte[], byte[], Cipher> Cipher { get; private set; }







        public CipherInfo(int keySize, Func<byte[], byte[], Cipher> cipher, bool isAead = false)
        {
            KeySize = keySize;
            Cipher = (key, iv) => cipher(key.Take(KeySize / 8), iv);
            IsAead = isAead;
        }
    }
}
