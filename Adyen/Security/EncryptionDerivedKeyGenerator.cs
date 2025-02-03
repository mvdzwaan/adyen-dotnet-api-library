using System.Security.Cryptography;
using System.Text;
using Adyen.Security.Extension;

namespace Adyen.Security
{
    internal class EncryptionDerivedKeyGenerator
    {
        private const int Iterations = 4000;
        private const string Salt = "AdyenNexoV1Salt";
        private static EncryptionDerivedKey CachedKey = null;

        internal EncryptionDerivedKey Generate(EncryptionCredentialDetails encryptionCredentialDetails)
        {
            if (CachedKey == null)
            {
                byte[] salt = Encoding.ASCII.GetBytes(Salt);

                var rfc2898 = new Rfc2898DeriveBytes(encryptionCredentialDetails.Password, salt, Iterations);
                byte[] key = rfc2898.GetBytes(80);

                CachedKey = new EncryptionDerivedKey
                {
                    HmacKey = key.Slice(0, EncryptionDerivedKey.HmacKeyLength),
                    CipherKey = key.Slice(EncryptionDerivedKey.HmacKeyLength, EncryptionDerivedKey.HmacKeyLength + EncryptionDerivedKey.CipherKeyLength),
                    IV = key.Slice(EncryptionDerivedKey.HmacKeyLength + EncryptionDerivedKey.CipherKeyLength, EncryptionDerivedKey.HmacKeyLength + EncryptionDerivedKey.CipherKeyLength + EncryptionDerivedKey.IVLength)
                };
            }

            return CachedKey;
        }
    }
}
