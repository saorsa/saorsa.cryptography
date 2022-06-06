using System.Security.Cryptography;

namespace Saorsa.Cryptography;

public class Aes128SymmetricCipher : SymmetricCipherBase<Aes>, ISymmetricCipher
{
    protected override Aes CreateSymmetricAlgorithm() 
    {
        var result = Aes.Create();

        result.KeySize = 128;

        return result;
    }
}
