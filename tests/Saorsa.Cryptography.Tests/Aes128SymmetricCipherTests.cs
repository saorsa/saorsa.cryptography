
namespace Saorsa.CoreLib.Tests.Cryptography;

public class Aes128SymmetricCipherTests
{
    [Test]
    public void TestSimpleUsage()
    {
        var cipher = new Aes128SymmetricCipher();

        var original = Guid.NewGuid().ToString();
        var password = $"{Guid.NewGuid()}{Guid.NewGuid()}";
        var salt = Guid.NewGuid().ToString();
        var encrypted = cipher.Encrypt(original, password, salt);
        var decrypted = cipher.Decrypt(encrypted, password, salt);

        Assert.That(decrypted, Is.EqualTo(original));
    }
}
