using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

using Jose;

namespace KeyGen
{

    public static class JWKHelper
    {
 


        // this assumes it's a key with headers and footers
        // we only want the base64 enc string 
        public static string GetPEMBase64(string pathToCert)
        {
            var lines = File.ReadAllLines(pathToCert);
            return String.Join("", lines.Skip(1).Take(lines.Count() - 2));

        }

        public static Jwk CreateJwkFromPrivateKeyPEM(string pathToCert)
        {
            var pemBase = GetPEMBase64(pathToCert);
            return MakeJwk(pemBase);
        }

        public static Jwk CreateJwk(string baseString)
        {
            return MakeJwk(baseString);
        }

        private static Jwk MakeJwk(string pemBase)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(Convert.FromBase64String(pemBase), out _);

            // create JWK from ECDsa key
            return new Jwk(ecdsa, isPrivate: true);
        }

        public static void SetSigJWKAttributes(Jwk jwk, string keyId = "signing-key")
        {
            jwk.KeyId = keyId;
            jwk.Use = "sig";
            jwk.Alg = "ES256";
        }
        public static void SetEncJWKAttributes(Jwk jwk, string keyId = "enc-key")
        {
            jwk.KeyId = keyId;
            jwk.Use = "enc";
            jwk.Alg = "ECDH-ES+A256KW";
        }

    }

}
