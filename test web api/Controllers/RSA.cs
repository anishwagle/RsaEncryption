using DataEncryption;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;

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

            if (c.Count == 0)
            {
                c[1] = new Cryptography();
            }

            var pk = c[1].GetPublicKey();
            var cipher = c[1].Encrypt(pk, key.Data);

            return Ok(new Response() { Data = cipher });
        }

        [HttpGet]
        [Route("getPk")]
        public string Getpk()
        {

            if (c.Count == 0)
            {
                c[1] = new Cryptography();
            }

            var pk = c[1].GetPublicKey();

            return pk;
        }
    }
}