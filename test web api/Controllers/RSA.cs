using DataEncryption;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Text;
//using Newtonsoft.Json;

namespace test_web_api.Controllers
{
    public class Request
    {
        public string Data { get; set; }
    }

    public class Response
    {
        public string Data { get; set; }
    }

    [ApiController]
    [Route("rsa")]
    public class RSA : ControllerBase
    {

        private readonly ILogger<RSA> _logger;
        public static ConcurrentDictionary<int,Cryptography> c = new ConcurrentDictionary<int, Cryptography>();

        public RSA(ILogger<RSA> logger)
        {
            //c = new ConcurrentDictionary<int,Cryptography>();
            _logger = logger;
        }

        [HttpPost]
        [Route("connect")]
        public async Task<IActionResult> GetPublicKey([FromBody] Request key)
        {
            try
            {
            if (c.Count == 0)
            {
                c[1] = new Cryptography();
            }
               // var obj = JsonConvert.DeserializeObject<Keys>(result);

                var keys = c[1].GetKeys();
           

                 var RsaEncodedAesKey = c[1].RsaEncrypt(keys.Aes, key.Data);

                keys.Aes = RsaEncodedAesKey;
                return Ok(keys);
            }catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [Route("check")]
        public async Task<IActionResult> CheckData([FromBody] AesResponse aesResponse)
        {
            try
            {

            if (c.Count == 0)
            {
                c[1] = new Cryptography();
            }

            var pk = c[1].GetKeys();
            //byte[] byteArray = Encoding.Unicode.GetBytes(pk.Rsa);
            var aesKey = Convert.FromBase64String(pk.Aes);
            var iv = Convert.FromBase64String(pk.AesIv);

            var receivedText= c[1].DecryptStringFromBytes_Aes(aesResponse.AesEncryptedData, aesKey, iv);
            return Ok(new Response()
            {
                Data = receivedText
            });
            }catch (Exception ex)
            {
               return BadRequest(ex.Message);
            }
        }

    }
}