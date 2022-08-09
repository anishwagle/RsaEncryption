using DataEncryption;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
//using System.Text.Json;
/*
// Create a new instance of the Aes
// class.  This generates a new key and initialization
// vector (IV).
//using Aes myAes = Aes.Create();
HttpClient client = new HttpClient();
var cry = new Cryptography();
//HttpResponseMessage response = await client.GetAsync($"https://localhost:5001/rsa/{cry.GetPublicKey()}");
//client.BaseAddress = new Uri("https://localhost:5001/rsa/connect");
var req = new Request()
{
Data = cry.GetPublicKey()
};
var data = new StringContent(JsonConvert.SerializeObject(req), Encoding.UTF8, "application/json");
var res = await client.PostAsync("https://localhost:5001/rsa/connect", data);
var result = await res.Content.ReadAsStringAsync();
var obj = JsonConvert.DeserializeObject<Response>(result);
var serverPublicKey = cry.RsaDecrypt(obj.Data);
Console.WriteLine(serverPublicKey);
Console.ReadLine(); */


string original = "The FitnessGram Pacer Test is a multistage aerobic capacity test that progressively gets more difficult as it continues. The 20 meter pacer test will begin in 30 seconds. Line up at the start. The running speed starts slowly, but gets faster each minute after you hear this signal. [beep] A single lap should be completed each time you hear this sound. [ding] Remember to run in a straight line, and run as long as possible. The second time you fail to complete a lap before the sound, your test is over. The test will begin on the word start. On your mark, get ready, start.";

// Create a new instance of the Aes
// class.  This generates a new key and initialization
// vector (IV).
using Aes myAes = Aes.Create();

HttpClient client = new HttpClient();

var cry = new Cryptography();

try
{
    var keys = cry.GetKeys();
    var req = new Request()
    {
        Data = keys.Rsa
    };

    var data = new StringContent(JsonConvert.SerializeObject(req), Encoding.UTF8, "application/json");
    var res = await client.PostAsync("https://localhost:5001/rsa/connect",data);
    var result = await res.Content.ReadAsStringAsync();
    var obj = JsonConvert.DeserializeObject<Keys>(result);
    //var serverPublicKey = obj.Data;

    var decryptedAesKey = cry.RsaDecrypt(obj.Aes);

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

//var RsaEncryptedAesKey = cry.RsaEncrypt(myAes.Key, cry.GetPublicKey());
//var DecryptedAesKey = cry.RsaDecrypt(RsaEncryptedAesKey);

//string AesDecryptedMessage = cry.DecryptStringFromBytes_Aes(AesEncryptedMessage, DecryptedAesKey, myAes.IV);

//Console.WriteLine($"Public Key:{cry.GetPublicKey()}\n");
//Console.WriteLine($"Rsa Encrypted Aes Key:{RsaEncryptedAesKey}\n");
//Console.WriteLine($"Decrypted Key:{DecryptedAesKey}\n");



//Console.WriteLine($"Message Encrypted With AES:{AesEncryptedMessage}\n");
//Console.WriteLine($"Message Decrypted with RSA Incrypted AES Key:{AesDecryptedMessage}\n");
