using Microsoft.Extensions.Configuration;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Serialization;

namespace DataEncryption
{
    public class Cryptography
    {
        public RSAParameters PublicKey { get; set; }
        public RSAParameters PrivateKey { get; set; }
        public RSA RSA { get; set; }
        public byte[] AesKey { get; set; }
        public byte[] AesIv { get; set; }
        public Cryptography()
        {
            RSA = GetRSACryptoProvider();
            PublicKey = RSA.ExportParameters(false);
            PrivateKey = RSA.ExportParameters(true);
            using Aes myAes = Aes.Create();
            AesKey= myAes.Key;
            AesIv = myAes.IV;
        }
        public Keys GetKeys()
        {
           
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, PublicKey);
            var test1Aes = Convert.ToBase64String(AesKey);
            var test2Aes = Encoding.UTF8.GetString(AesKey);
            //var test1AesIv = Convert.ToBase64String(AesIv);
           /* return new Keys
            {
                Rsa = sw.ToString(),
                Aes = Convert.ToBase64String(AesKey),
                AesIv = Convert.ToBase64String(AesIv)
            };  */
            return new Keys
            {
                Rsa = sw.ToString(),
               // Aes = Encoding.UTF8.GetString(AesKey),
                Aes = Convert.ToBase64String(AesKey),
                AesIv = Convert.ToBase64String(AesIv)
            };


            // return sw.ToString();
        }

        public RSAParameters StringToRsa(string key)
        {
            byte[] byteArray = Encoding.Unicode.GetBytes(key);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            MemoryStream stream = new MemoryStream(byteArray);
            var xs = new XmlSerializer(typeof(RSAParameters));
            return (RSAParameters)xs.Deserialize(stream);
        }
         public string RsaEncrypt(string plainText,string key)
        {
            RSA.ImportParameters(StringToRsa(key));
            var plainTextBytes = Encoding.Unicode.GetBytes(plainText);
            var cipherTextBytes = RSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);
            var cipherText = Convert.ToBase64String(cipherTextBytes);
            return cipherText;
        }


        public string RsaDecrypt(string cypher)
         {
             RSA.ImportParameters(PrivateKey);
            // RSA.ImportParameters(PublicKey);
             var cypherBytes = Convert.FromBase64String(cypher);
             var textBytes = RSA.Decrypt(cypherBytes, RSAEncryptionPadding.Pkcs1);
             var message = Encoding.Unicode.GetString(textBytes);
             return message;

         } 

        private RSA GetRSACryptoProvider()
        {
            try
            {
                var rsa = RSA.Create();
                rsa.KeySize = 2048;
                return rsa;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in GetRSACryptoProvider(): {ex}");
                return null;
            }
        }

        public AesResponse EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return new AesResponse
            {
                AesEncryptedData = encrypted,
            };
        }

        public string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        //////////////////////////////////////
        /////////////////////////////////////
        public string EncryptUsingCertificate(string data)
        {
            try
            {
                byte[] byteData = Encoding.UTF8.GetBytes(data);
                //string path = Path.Combine("root", "mycert.pem");
                var buildDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string path = @"D:\\Dev\\Encryption\\RsaEncryption\\DataEncryption\\root\\mycert.pem";
                var collection = new X509Certificate2Collection();
                collection.Import(path);
                var certificate = collection[0];
                var output = "";
                using (RSA csp = (RSA)certificate.PublicKey.Key)
                {
                    byte[] bytesEncrypted = csp.Encrypt(byteData, RSAEncryptionPadding.OaepSHA1);
                    output = Convert.ToBase64String(bytesEncrypted);
                }
                return output;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public string DecryptUsingCertificate(string data)
        {
            try
            {
                byte[] byteData = Convert.FromBase64String(data);
                //string path = Path.Combine("root", "mycertprivatekey.pfx");
                string path = @"D:\\Dev\\Encryption\\RsaEncryption\\DataEncryption\\root\\mycertprivatekey.pfx";
                var Password = "kp686d8t7x"; //Password That We Have Put On Generate Keys  
                var collection = new X509Certificate2Collection();
                collection.Import(System.IO.File.ReadAllBytes(path), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                X509Certificate2 certificate = new X509Certificate2();
                certificate = collection[0];
                foreach (var cert in collection)
                {
                    if (cert.FriendlyName.Contains("my certificate"))
                    {
                        certificate = cert;
                    }
                }
                if (certificate.HasPrivateKey)
                {
                    RSA csp = (RSA)certificate.PrivateKey;
                    var privateKey = certificate.PrivateKey as RSACryptoServiceProvider;
                    var keys = Encoding.UTF8.GetString(csp.Decrypt(byteData, RSAEncryptionPadding.OaepSHA1));
                   
                    return keys;
                }
            }
            catch (Exception ex) { }
            return null;
        }

    }
}

