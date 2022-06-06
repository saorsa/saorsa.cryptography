using System.Security.Cryptography;

namespace Saorsa.Cryptography;

public class Aes256SymmetricCipher : SymmetricCipherBase<Aes>, ISymmetricCipher
{
    protected override Aes CreateSymmetricAlgorithm()
    {
        var result = Aes.Create();

        result.KeySize = 256;

        return result;
    }
}
