using DataEncryption;
using System.Security.Cryptography;

string original = "Here is some data to encrypt!";

// Create a new instance of the Aes
// class.  This generates a new key and initialization
// vector (IV).
using Aes myAes = Aes.Create();

var cry= new Cryptography();
var cipher = cry.Encrypt(original,cry.GetPublicKey());
var message = cry.Decrypt(cipher);
Console.WriteLine($"Public Key:{cry.GetPublicKey()}\n");
Console.WriteLine($"Cypher:{cipher}\n");
Console.WriteLine($"Message:{message}\n");
// Decrypt the bytes to a string.
//string roundtrip = Cryptography.DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

//Display the original data and the decrypted data.
Console.WriteLine("Original:   {0}", original);
//Console.WriteLine("Round Trip: {0}", roundtrip);
