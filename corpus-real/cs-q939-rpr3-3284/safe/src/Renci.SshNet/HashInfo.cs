using System;
using System.Security.Cryptography;

using Renci.SshNet.Common;

namespace Renci.SshNet
{



    public class HashInfo
    {






        public int KeySize { get; private set; }







        public bool IsEncryptThenMAC { get; private set; }





        public Func<byte[], HashAlgorithm> HashAlgorithm { get; private set; }







        public HashInfo(int keySize, Func<byte[], HashAlgorithm> hash, bool isEncryptThenMAC = false)
        {
            KeySize = keySize;
            HashAlgorithm = key => hash(key.Take(KeySize / 8));
            IsEncryptThenMAC = isEncryptThenMAC;
        }
    }
}
