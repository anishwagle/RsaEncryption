using DataEncryption;
using System.Security.Cryptography;
using System.Text;
using AES_Implementation;
using Newtonsoft.Json;

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
var serverPublicKey = cry.Decrypt(obj.Data);
Console.WriteLine(serverPublicKey);
Console.ReadLine();
