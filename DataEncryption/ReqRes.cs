using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataEncryption
{
    public class Request
    {
        public string Data { get; set; }
    }

    public class Response
    {
        public string Data { get; set; }
    }
    public class AesResponse {

        public byte[]? AesEncryptedData { get; set; }

    }

    public class Keys
    {
        public string? Rsa { get; set; }
        public string? Aes { get; set; }
        public string? AesIv { get; set; }
    }

}
