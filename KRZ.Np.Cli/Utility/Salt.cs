using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KRZ.Np.Cli.Utility
{
    public static class Salt
    {
        public const int SaltLengthLimit = 32;

        public static byte[] GetSalt()
        {
            var salt = new byte[SaltLengthLimit];
            using (var random = new RNGCryptoServiceProvider())
            {
                random.GetNonZeroBytes(salt);
            }

            return salt;
        }
    }
}
