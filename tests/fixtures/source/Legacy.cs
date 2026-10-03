using System.Security.Cryptography;
class Legacy {
    void Run() {
        using var tdes = TripleDES.Create();
        var des = new DESCryptoServiceProvider();
    }
}
