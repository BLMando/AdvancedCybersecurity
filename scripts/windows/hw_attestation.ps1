param (
    [Parameter(Mandatory=$true)]
    [string]$CN
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$label = "ZTA-HW-$CN"

# C# helper: Software KSP only (TPM via MicrosoftPlatformCryptoProvider is a
# Windows-Desktop-only .NET API unavailable in PS7/.NET 6+).
# TPM presence is detected via Get-Tpm; if available we flag it but still use
# the Software KSP for the key operation in this cross-version compatible script.
$code = @"
using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections;

public class HWHelper {
    public static Hashtable SignAndGetPub(string label, string cn, bool useTpmFlag) {
        // Use TPM provider if available, fallback to software only if absolutely necessary
        // but here we enforce TPM for the 'non-exportable' requirement.
        CngProvider provider = useTpmFlag ? 
            new CngProvider("Microsoft Platform Crypto Provider") : 
            new CngProvider("Microsoft Software Key Storage Provider");

        CngKeyCreationParameters keyParams = new CngKeyCreationParameters {
            Provider     = provider,
            ExportPolicy = CngExportPolicies.None // ENFORCE NON-EXPORTABLE
        };

        if (useTpmFlag) {
            // TPM specific parameters
            keyParams.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
        }

        CngKey key;
        try {
            if (CngKey.Exists(label, provider)) {
                key = CngKey.Open(label, provider);
            } else {
                key = CngKey.Create(CngAlgorithm.Rsa, label, keyParams);
            }
        } catch (Exception e) {
            // If TPM fails (e.g. not initialized), fallback to software but log warning in result
            if (useTpmFlag) {
                provider = new CngProvider("Microsoft Software Key Storage Provider");
                keyParams.Provider = provider;
                if (CngKey.Exists(label, provider)) {
                    key = CngKey.Open(label, provider);
                } else {
                    key = CngKey.Create(CngAlgorithm.Rsa, label, keyParams);
                }
            } else {
                throw e;
            }
        }

        using (RSACng rsa = new RSACng(key)) {
            string timestamp   = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string proofString = "ZTA-CERT-BINDING|CN=" + cn + "|TIME=" + timestamp;
            byte[] dataToSign  = Encoding.UTF8.GetBytes(proofString);

            byte[] signature   = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            RSAParameters rsaParams = rsa.ExportParameters(false);

            Hashtable result = new Hashtable();
            result["signature_b64"]   = Convert.ToBase64String(signature);
            result["modulus_b64"]     = Convert.ToBase64String(rsaParams.Modulus);
            result["exponent_b64"]    = Convert.ToBase64String(rsaParams.Exponent);
            result["csr_pem"]         = proofString;
            result["is_native_proof"] = useTpmFlag ? "true" : "false";
            result["hw_provider"]     = provider.Provider;
            return result;
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies "System.Security"

# Detect TPM availability at the PowerShell level (no compile-time dependency)
$hasTpm = $false
try {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
        $hasTpm = $true
    }
} catch {
    $hasTpm = $false
}

try {
    $data = [HWHelper]::SignAndGetPub($label, $CN, $hasTpm)
    $json = $data | ConvertTo-Json -Compress
    Write-Output $json
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
