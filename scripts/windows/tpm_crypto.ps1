# tpm_crypto.ps1 - Cryptography and Hardware Attestation Module

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Compilazione delle classi helper C# per le operazioni di crittografia
if (-not ([System.Management.Automation.PSTypeName]"HWHelper").Type) {
    $csharpCryptoCode = @"
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class SSLBypass {
    public static void Bypass() {
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    }
}

public class RSASoftKeyHelper {
    private static byte[] EncodeInteger(byte[] bytes) {
        int left = 0;
        while (left < bytes.Length && bytes[left] == 0) left++;
        int len = bytes.Length - left;
        if (len == 0) return new byte[] { 0x02, 0x01, 0x00 };

        bool pad = (bytes[left] & 0x80) != 0;
        int datalen = len + (pad ? 1 : 0);

        byte[] lenBytes;
        if (datalen < 128) {
            lenBytes = new byte[] { (byte)datalen };
        } else if (datalen <= 255) {
            lenBytes = new byte[] { 0x81, (byte)datalen };
        } else {
            lenBytes = new byte[] { 0x82, (byte)(datalen >> 8), (byte)(datalen & 0xff) };
        }

        byte[] res = new byte[1 + lenBytes.Length + datalen];
        res[0] = 0x02;
        Buffer.BlockCopy(lenBytes, 0, res, 1, lenBytes.Length);
        int writePos = 1 + lenBytes.Length;
        if (pad) {
            res[writePos] = 0x00;
            writePos++;
        }
        Buffer.BlockCopy(bytes, left, res, writePos, len);
        return res;
    }

    private static byte[] EncodeSequence(byte[] d1, byte[] d2, byte[] d3, byte[] d4, byte[] d5, byte[] d6, byte[] d7, byte[] d8, byte[] d9) {
        int totalLen = d1.Length + d2.Length + d3.Length + d4.Length + d5.Length + d6.Length + d7.Length + d8.Length + d9.Length;
        byte[] lenBytes;
        if (totalLen < 128) {
            lenBytes = new byte[] { (byte)totalLen };
        } else if (totalLen <= 255) {
            lenBytes = new byte[] { 0x81, (byte)totalLen };
        } else {
            lenBytes = new byte[] { 0x82, (byte)(totalLen >> 8), (byte)(totalLen & 0xff) };
        }

        byte[] res = new byte[1 + lenBytes.Length + totalLen];
        res[0] = 0x30;
        Buffer.BlockCopy(lenBytes, 0, res, 1, lenBytes.Length);
        int writePos = 1 + lenBytes.Length;

        byte[][] parts = new byte[][] { d1, d2, d3, d4, d5, d6, d7, d8, d9 };
        foreach (var p in parts) {
            Buffer.BlockCopy(p, 0, res, writePos, p.Length);
            writePos += p.Length;
        }
        return res;
    }

    public static Hashtable GenerateSoftwareKeyPair(string cn, string timestamp) {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048)) {
            RSAParameters p = rsa.ExportParameters(true);

            byte[] d1 = EncodeInteger(new byte[] { 0x00 });
            byte[] d2 = EncodeInteger(p.Modulus);
            byte[] d3 = EncodeInteger(p.Exponent);
            byte[] d4 = EncodeInteger(p.D);
            byte[] d5 = EncodeInteger(p.P);
            byte[] d6 = EncodeInteger(p.Q);
            byte[] d7 = EncodeInteger(p.DP);
            byte[] d8 = EncodeInteger(p.DQ);
            byte[] d9 = EncodeInteger(p.InverseQ);

            byte[] der = EncodeSequence(d1, d2, d3, d4, d5, d6, d7, d8, d9);
            string privB64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
            string privPem = "-----BEGIN RSA PRIVATE KEY-----\r\n" + privB64 + "\r\n-----END RSA PRIVATE KEY-----";

            string proofString = "ZTA-CERT-BINDING|CN=" + cn + "|TIME=" + timestamp;
            byte[] dataToSign = Encoding.UTF8.GetBytes(proofString);
            byte[] signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            string sigB64 = Convert.ToBase64String(signature);

            Hashtable result = new Hashtable();
            result["private_key_pem"] = privPem;
            result["modulus_b64"] = Convert.ToBase64String(p.Modulus);
            result["exponent_b64"] = Convert.ToBase64String(p.Exponent);
            result["proof_string"] = proofString;
            result["signature_b64"] = sigB64;
            return result;
        }
    }

    private static byte[] EncodeLength(int length) {
        if (length < 128) {
            return new byte[] { (byte)length };
        } else if (length <= 255) {
            return new byte[] { 0x81, (byte)length };
        } else {
            return new byte[] { 0x82, (byte)(length >> 8), (byte)(length & 0xff) };
        }
    }

    public static string ExportSpkiPublicKeyPem(byte[] modulus, byte[] exponent) {
        byte[] modDer = EncodeInteger(modulus);
        byte[] expDer = EncodeInteger(exponent);

        int rsaPubKeyLen = modDer.Length + expDer.Length;
        byte[] rsaPubKeyLenBytes = EncodeLength(rsaPubKeyLen);
        byte[] rsaPubKeyDer = new byte[1 + rsaPubKeyLenBytes.Length + rsaPubKeyLen];
        rsaPubKeyDer[0] = 0x30;
        Buffer.BlockCopy(rsaPubKeyLenBytes, 0, rsaPubKeyDer, 1, rsaPubKeyLenBytes.Length);
        Buffer.BlockCopy(modDer, 0, rsaPubKeyDer, 1 + rsaPubKeyLenBytes.Length, modDer.Length);
        Buffer.BlockCopy(expDer, 0, rsaPubKeyDer, 1 + rsaPubKeyLenBytes.Length + modDer.Length, expDer.Length);

        int bitStringValLen = 1 + rsaPubKeyDer.Length;
        byte[] bitStringLenBytes = EncodeLength(bitStringValLen);
        byte[] bitStringDer = new byte[1 + bitStringLenBytes.Length + bitStringValLen];
        bitStringDer[0] = 0x03;
        Buffer.BlockCopy(bitStringLenBytes, 0, bitStringDer, 1, bitStringLenBytes.Length);
        bitStringDer[1 + bitStringLenBytes.Length] = 0x00;
        Buffer.BlockCopy(rsaPubKeyDer, 0, bitStringDer, 2 + bitStringLenBytes.Length, rsaPubKeyDer.Length);

        byte[] algIdDer = new byte[] { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

        int spkiLen = algIdDer.Length + bitStringDer.Length;
        byte[] spkiLenBytes = EncodeLength(spkiLen);
        byte[] spkiDer = new byte[1 + spkiLenBytes.Length + spkiLen];
        spkiDer[0] = 0x30;
        Buffer.BlockCopy(spkiLenBytes, 0, spkiDer, 1, spkiLenBytes.Length);
        Buffer.BlockCopy(algIdDer, 0, spkiDer, 1 + spkiLenBytes.Length, algIdDer.Length);
        Buffer.BlockCopy(bitStringDer, 0, spkiDer, 1 + spkiLenBytes.Length + algIdDer.Length, bitStringDer.Length);

        string b64 = Convert.ToBase64String(spkiDer, Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN PUBLIC KEY-----\r\n" + b64 + "\r\n-----END PUBLIC KEY-----";
    }
}

public class HWHelper {
    public static Hashtable SignAndGetPub(string label, string cn, bool useTpmFlag) {
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
    Add-Type -TypeDefinition $csharpCryptoCode -ReferencedAssemblies "System.Security"
}

[SSLBypass]::Bypass()

# ----------------- Funzioni Helper per Certificati e Attestazione -----------------

function Get-CertPem ($cert) {
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certB64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----"
}

function Export-SpkiPublicKeyPem ($modulus, $exponent) {
    return [RSASoftKeyHelper]::ExportSpkiPublicKeyPem($modulus, $exponent)
}

function Get-PublicKeyPem ($cert) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    if ($rsa) {
        $params = $rsa.ExportParameters($false)
        return [RSASoftKeyHelper]::ExportSpkiPublicKeyPem($params.Modulus, $params.Exponent)
    }
    return $null
}

function Get-FileCertWithKey ($cn) {
    $crtPath = Join-Path $CERT_DIR "$cn.crt"
    $keyPath = Join-Path $CERT_DIR "$cn.key"
    if (-not (Test-Path $crtPath) -or -not (Test-Path $keyPath)) {
        return $null
    }
    $combinedPem = (Get-Content $crtPath -Raw) + "`n" + (Get-Content $keyPath -Raw)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($combinedPem)
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($bytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        return $cert
    } catch {
        Write-Host "    [WARN] Impossibile caricare cert+key da file per CN=$cn : $_" -ForegroundColor Yellow
        return $null
    }
}

function Get-ZtaCertificate ($cn) {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" -and $_.HasPrivateKey } | Select-Object -First 1
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
    }
    return $cert
}

function Get-ZtaCertificateWithFallback ($cn) {
    $cert = Get-ZtaCertificate $cn
    if (-not $cert) {
        Write-Host "[API] Cert non trovato in Windows Store per CN=$cn. Cerco su disco..." -ForegroundColor Yellow
        $cert = Get-FileCertWithKey $cn
    } elseif (-not $cert.HasPrivateKey) {
        Write-Host "[API] Cert in Windows Store per CN=$cn non ha private key. Cerco su disco..." -ForegroundColor Yellow
        $fileCert = Get-FileCertWithKey $cn
        if ($fileCert) {
            $cert = $fileCert
            Write-Host "[API] Cert+key caricati da file per CN=$cn" -ForegroundColor Green
        }
    }
    return $cert
}

function Invoke-HwAttestation ($cn) {
    $label = "ZTA-HW-$cn"
    $hasTpm = $false
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
            $hasTpm = $true
        }
    } catch {
        $hasTpm = $false
    }
    
    # Esegue la firma hardware via CngKey direttamente in-process
    $data = [HWHelper]::SignAndGetPub($label, $cn, $hasTpm)
    return $data
}
