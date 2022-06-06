using System.Security.Cryptography;
using System.Text;

namespace Saorsa.Cryptography;

public abstract class SymmetricCipherBase<T> where T : SymmetricAlgorithm
{
    protected abstract T CreateSymmetricAlgorithm();
    
    public virtual string Encrypt(string original, string password, string salt)
    {
        using var passwordDerivation = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));
        using var algorithm = CreateSymmetricAlgorithm();
        var rgbKey = passwordDerivation.GetBytes(algorithm.KeySize >> 3);
        var rgbIV = passwordDerivation.GetBytes(algorithm.BlockSize >> 3);

        using var encryptor = algorithm.CreateEncryptor(rgbKey, rgbIV);
        using var memoryBuffer = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryBuffer, encryptor, CryptoStreamMode.Write);
        using (var writer = new StreamWriter(cryptoStream, Encoding.Unicode))
        {
            writer.Write(original);
        }
        
        return Uri.UnescapeDataString(
            Convert.ToBase64String(memoryBuffer.ToArray())
        );
    }

    public virtual string Decrypt(string encrypted, string password, string salt)
    {
        encrypted = Uri.UnescapeDataString(encrypted);

        using var passwordDerivation = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));
        using var algorithm = CreateSymmetricAlgorithm();
        var rgbKey = passwordDerivation.GetBytes(algorithm.KeySize >> 3);
        var rgbIV = passwordDerivation.GetBytes(algorithm.BlockSize >> 3);

        using var deCryptoTransform = algorithm.CreateDecryptor(rgbKey, rgbIV);
        using var buffer = new MemoryStream(Convert.FromBase64String(encrypted));
        using var stream = new CryptoStream(buffer, deCryptoTransform, CryptoStreamMode.Read);
        using var reader = new StreamReader(stream, Encoding.Unicode);
        return reader.ReadToEnd();
    }
}
