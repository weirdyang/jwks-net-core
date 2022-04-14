using System;
using System.Collections.Generic;

namespace KeyGen
{

    public class SingPassOptions
    {
        private string _serverJwksUri;

        // this is read from 
        // https://id.singpass.gov.sg/.well-known/openid-configuration
        private readonly string EncValueSupported = "A256CBC_HS512";
        public string Authority { get; set; } = "https://id.singpass.gov.sg";
        public string ClientId { get; set; } = "default-clientid";

        public string ServerJwksUri
        {
            get
            {
                return _serverJwksUri ?? $"{Authority}/.well-known/keys";
            }
            set
            {
                _serverJwksUri = value;
            }
        }
        public int SkewInMinutes { get; set; } = 2;

        public SigningAlgorithm SigningAlgorithm { get; set; } = SigningAlgorithm.ES256;
        public string ServerJwks { get; internal set; }

        public Dictionary<string, object> ConstructClaims()
        {
            var now = DateTimeOffset.UtcNow;
            return new Dictionary<string, object>()
                {
                    {"sub", this.ClientId },
                    {"aud", this.Authority },
                    {"iss", this.ClientId },
                    {"iat", now.ToUnixTimeSeconds() },
                    {"exp", now.AddMinutes(SkewInMinutes).ToUnixTimeSeconds()}
                };
        }
    }
}
