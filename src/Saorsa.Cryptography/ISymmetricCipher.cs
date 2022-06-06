namespace Saorsa.Cryptography;

public interface ISymmetricCipher
{
    string Decrypt(string encrypted, string password, string salt);

    string Encrypt(string original, string password, string salt);
}
