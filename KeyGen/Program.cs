
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Jose;
using Microsoft.IdentityModel.Tokens;

namespace KeyGen
{
    internal partial class Program
    {
        public static string GetFilePath(string certFolder, string name)
        {
            return Path.Combine(Directory.GetCurrentDirectory(), "certs", certFolder, name);
        }
        static void Main(string[] args)
        {
            var options = new SingPassOptions();

            // create signing to sign the client assertion
            var signJwk = JWKHelper.CreateJwkFromPrivateKeyPEM(GetFilePath("signing", "private.pem"));

            JWKHelper.SetSigJWKAttributes(signJwk);

            var payload = options.ConstructClaims();

            var clientAssertionToken = Jose.JWT.Encode(payload, signJwk, algorithm: JwsAlgorithm.ES256);

            var publicKey = new Jwk(crv: "P-256", x: "TU7MnKXI-77yn1udb7tANpIYCk2n-Aju9cULUj4MniI", y: "JgDt25h32C9f0-KWL5gf--k2HLpCF9P0dOd3ka1OySg");

            var check = Jose.JWT.Decode(clientAssertionToken, publicKey);

            var verify = JsonSerializer.Deserialize<Dictionary<string, object>>(check);

            // create encryption to decrypt the id token
            var encJwk = JWKHelper.CreateJwkFromPrivateKeyPEM(GetFilePath("encrypting", "private.pem"));

            JWKHelper.SetEncJWKAttributes(encJwk);

            // get public key from singpass
            // https://id.singpass.gov.sg/.well-known/keys
            using var webClient = new WebClient();
            options.ServerJwks = webClient.DownloadString(options.ServerJwksUri);
            var singpassKeys = options.ServerJwks;


            // data is a JWS in JWE
            // encrypted using the public JWK from the encJwk
            var encryptedIdToken = @"eyJraWQiOiJuZGlfc3RnXzAxIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJ5MVRzZkk4Zk5LM0tyblYwUVVETnZzdzFOU1RFY1RCbSIsInN1YiI6InM9Uzg4MjkzMTRCLHU9MWMwY2VlMzgtM2E4Zi00ZjhhLTgzYmMtN2EwZTRjNTlkNmE5IiwiYW1yIjpbInB3ZCIsInN3ayJdLCJpc3MiOiJodHRwczpcL1wvc3RnLWlkLnNpbmdwYXNzLmdvdi5zZyIsImV4cCI6MTY0OTgzNjk5MSwiaWF0IjoxNjQ5ODM2MzkxLCJub25jZSI6InNxY2RMa1wvcUd6R2hicWNJYm9ycjNcL3doWTFXRTJudkxmanRLcnlrNlpsTT0ifQ.XS2mwAjEIKkJqYgW74SDV1iHyrobcnE9dLZ2maPk8RegGmE0K1EBvKjNOi907j0LW2dlpX9hbBToqGjA2DUeDg";


            // we simulate it
            JweRecipient client = new JweRecipient(JweAlgorithm.ECDH_ES_A256KW, encJwk);
            var secretStuff = JWE.Encrypt(clientAssertionToken,new[] { client }, JweEncryption.A256CBC_HS512);

            string myToken = Jose.JWT.Encode(secretStuff, signJwk, JweAlgorithm.ECDH_ES_A256KW, JweEncryption.A128CBC_HS256);
            // decrypt
            var results = JWE.Decrypt(encryptedIdToken, encJwk).Plaintext;

            // validate
            var sgpPublicKey = JwkSet.FromJson(singpassKeys, Jose.JWT.DefaultSettings.JsonMapper);
           
            var claims = JWT.Decode(results, sgpPublicKey);


            // trying to use JwtSecurityTokenHandler
            var handler = new JwtSecurityTokenHandler();
            var validParams = new TokenValidationParameters
            {
                IssuerSigningKeyResolver = (token, securityToken, kid, tokenValidation) =>
                {
                    if (string.IsNullOrEmpty(options.ServerJwks))
                    {
                        using var webClient = new WebClient();
                        options.ServerJwks = webClient.DownloadString(options.ServerJwksUri);
                    }
                    return new JsonWebKeySet(options.ServerJwks).GetSigningKeys();
                },
                ValidAudience = options.ClientId,
                ValidIssuer = options.Authority,
                ValidateIssuer = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true
            };
            // var final = JWT.Decode(results, singpassKeys);
            var validated = handler.ValidateToken(results, validParams, out var securityToken);


            var keySet = new JwkSet(signJwk, encJwk);

            string keysetJson = keySet.ToJson(Jose.JWT.DefaultSettings.JsonMapper);

        }

    }
}
