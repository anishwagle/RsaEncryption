using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace DataEncryption
{
    public class Cryptography
    {
        public RSAParameters PublicKey { get; set; }
        public RSAParameters PrivateKey { get; set; }
        public RSA RSA { get; set; }

        public Cryptography()
        {
            RSA = GetRSACryptoProvider();
            PublicKey = RSA.ExportParameters(false); 
            PrivateKey = RSA.ExportParameters(true);
            
        }
        public string GetPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, PublicKey);

            
            return sw.ToString();
        }

        public RSAParameters StringToRsa(string key)
        {
            byte[] byteArray = Encoding.Unicode.GetBytes(key);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            MemoryStream stream = new MemoryStream(byteArray);
            var xs = new XmlSerializer(typeof(RSAParameters));
           return (RSAParameters)xs.Deserialize(stream);
        }
        public string Encrypt(string plainText,string key)
        {
            RSA.ImportParameters(StringToRsa(key));
            var plainTextBytes = Encoding.Unicode.GetBytes(plainText);
            var cipherTextBytes = RSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);
            var cipherText = Convert.ToBase64String(cipherTextBytes);
            return cipherText;


        }


        public string Decrypt(string cypher)
        {
            RSA.ImportParameters(PrivateKey);
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
                rsa.KeySize = 8192;
                return rsa;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in GetRSACryptoProvider(): {ex}");
                return null;
            }
        }

    }
}