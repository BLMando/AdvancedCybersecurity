param (
    [Parameter(Mandatory=$true)]
    [string]$CN
)

$label = "ZTA-HW-$CN"

# C# helper to interact with TPM (NCrypt)
$code = @"
using System;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Collections.Generic;

public class TPMHelper {
    public static string SignAndGetPub(string label, string cn) {
        CngKeyCreationParameters keyParams = new CngKeyCreationParameters {
            Provider = CngProvider.MicrosoftPlatformCryptoProvider, // This forces TPM
            ExportPolicy = CngExportPolicies.None
        };
        
        CngKey key;
        if (!CngKey.Exists(label)) {
            key = CngKey.Create(CngAlgorithm.Rsa, label, keyParams);
        } else {
            key = CngKey.Open(label);
        }

        using (RSACng rsa = new RSACng(key)) {
            // 1. Prepare Proof String
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string proofString = "ZTA-CERT-BINDING|CN=" + cn + "|TIME=" + timestamp;
            byte[] dataToSign = Encoding.UTF8.GetBytes(proofString);

            // 2. Sign
            byte[] signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            
            // 3. Public Key in PEM format
            byte[] pubKeyBytes = rsa.ExportRSAPublicKey();
            string pubKeyBase64 = Convert.ToBase64String(pubKeyBytes, Base64FormattingOptions.InsertLineBreaks);
            string pubKeyPEM = "-----BEGIN RSA PUBLIC KEY-----\n" + pubKeyBase64 + "\n-----END RSA PUBLIC KEY-----";

            var result = new Dictionary<string, string> {
                { "signature_b64", Convert.ToBase64String(signature) },
                { "pub_key_b64", Convert.ToBase64String(pubKeyBytes) },
                { "pub_key_pem", pubKeyPEM },
                { "csr_pem", proofString },
                { "is_native_proof", "true" }
            };

            return new JavaScriptSerializer().Serialize(result);
        }
    }
}
"@

# Note: JavaScriptSerializer requires System.Web.Extensions which might not be in all PS environments
# We use a simpler JSON construction if needed, but for now let's try this.
Add-Type -TypeDefinition $code -ReferencedAssemblies "System.Security", "System.Web.Extensions"

try {
    $result = [TPMHelper]::SignAndGetPub($label, $CN)
    Write-Output $result
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
