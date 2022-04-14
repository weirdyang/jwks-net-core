using System.ComponentModel;

namespace KeyGen
{

        public enum SigningAlgorithm
        {
            [Description("ES256")]
            ES256 = 1,
            [Description("ES384")]
            ES384 = 2,
            [Description("ES512")]
            ES512 = 3
        }

}
