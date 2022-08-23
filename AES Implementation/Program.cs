using DataEncryption;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;


string original = "The FitnessGram Pacer Test is a multistage aerobic capacity test that progressively gets more difficult as it continues. The 20 meter pacer test will begin in 30 seconds. Line up at the start. The running speed starts slowly, but gets faster each minute after you hear this signal. [beep] A single lap should be completed each time you hear this sound. [ding] Remember to run in a straight line, and run as long as possible. The second time you fail to complete a lap before the sound, your test is over. The test will begin on the word start. On your mark, get ready, start.";


using Aes myAes = Aes.Create();

HttpClient client = new HttpClient();

var cry = new Cryptography();
/*
try
{
    var keys = cry.GetKeys();
    var req = new Request()
    {
        Data = keys.Rsa
    };
    var certEncrypt = cry.EncryptUsingCertificate("Testtt");
    var certDecrypt = cry.DecryptUsingCertificate(certEncrypt);
    
    var data = new StringContent(JsonConvert.SerializeObject(req), Encoding.UTF8, "application/json");
    var res = await client.GetAsync("https://localhost:5001/rsa/connect");
    var result = await res.Content.ReadAsStringAsync();
    var obj = JsonConvert.DeserializeObject<Keys>(result);
    //var serverPublicKey = obj.Data;

    var decryptedAesKey = cry.DecryptUsingCertificate(obj.Aes);

    AesResponse AesEncryptedMessage = cry.EncryptStringToBytes_Aes(original, Convert.FromBase64String(decryptedAesKey), Convert.FromBase64String(obj.AesIv));
    //AesEncryptedMessage.AesKey = cry.RsaEncrypt(myAes.Key, serverPublicKey);
    //AesEncryptedMessage.Iv = cry.RsaEncrypt(myAes.IV, serverPublicKey);

    var data2 = new StringContent(JsonConvert.SerializeObject(AesEncryptedMessage), Encoding.UTF8, "application/json");
    var res2 = await client.PostAsync("https://localhost:5001/rsa/check", data2);
    var text= await res2.Content.ReadAsStringAsync();
    var decrypted= JsonConvert.DeserializeObject<Response>(text);
    Console.WriteLine($"Original Message:{original}\n");
    Console.WriteLine($"Decrypted Message:{decrypted.Data}\n");
   
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}
*/

try
{
    var keys = cry.GetKeys();
    var req = new Keys()
    {
        Rsa = null,
        Aes = cry.EncryptUsingCertificate(keys.Aes),
        AesIv= keys.AesIv
    };
    //var certEncrypt = cry.EncryptUsingCertificate("Testtt");
    //var certDecrypt = cry.DecryptUsingCertificate(certEncrypt);

    var data = new StringContent(JsonConvert.SerializeObject(req), Encoding.UTF8, "application/json");
    var res = await client.PostAsync("https://localhost:5001/rsa/certcheck",data);
    var result = await res.Content.ReadAsStringAsync();
    var obj = JsonConvert.DeserializeObject<Response>(result);
    //var serverPublicKey = obj.Data;

    var AesDecryptedMessage = cry.DecryptStringFromBytes_Aes(Convert.FromBase64String(obj.Data), Convert.FromBase64String(keys.Aes), Convert.FromBase64String(keys.AesIv));
    Console.WriteLine($"Decrypted Message:{AesDecryptedMessage}\n");

}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}


