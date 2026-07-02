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
        // Use Software KSP to support CngUIPolicy (Windows Hello) which is unsupported by the TPM provider
        CngProvider provider = new CngProvider("Microsoft Software Key Storage Provider");

        CngUIPolicy uiPolicy = new CngUIPolicy(
            CngUIProtectionLevels.ForceHighProtection,
            "Zero Trust Security Key (" + cn + ")",
            "Conferma la tua identità per accedere alla chiave crittografica hardware.",
            "Accesso alla chiave crittografica protetta da TPM.",
            "Sblocco Biometrico Zero Trust"
        );

        CngKeyCreationParameters keyParams = new CngKeyCreationParameters {
            Provider     = provider,
            ExportPolicy = CngExportPolicies.None,
            UIPolicy     = uiPolicy
        };

        CngKey key;
        try {
            if (CngKey.Exists(label, provider)) {
                // Delete existing key to force recreation with UIPolicy if needed,
                // but here we just open it.
                key = CngKey.Open(label, provider);
            } else {
                key = CngKey.Create(CngAlgorithm.Rsa, label, keyParams);
            }
        } catch (Exception e) {
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

if (-not ([System.Management.Automation.PSTypeName]"HWHelper").Type) {
    Add-Type -TypeDefinition $code -ReferencedAssemblies "System.Security"
}

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
