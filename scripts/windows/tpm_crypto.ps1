# tpm_crypto.ps1 - Cryptographic C# helper for Windows CNG/TPM
$code = @"
using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections;
using System.Net;

public class ZtaCryptoHelper {
    public static void BypassSsl() {
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    }

    public static Hashtable GenerateTpmKeyAndSign(string label, string cn, bool useTpm) {
        CngProvider provider = useTpm ? 
            new CngProvider("Microsoft Platform Crypto Provider") : 
            new CngProvider("Microsoft Software Key Storage Provider");

        CngKeyCreationParameters keyParams = new CngKeyCreationParameters {
            Provider     = provider,
            ExportPolicy = CngExportPolicies.None
        };

        if (useTpm) {
            keyParams.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
        }

        CngKey key;
        try {
            if (CngKey.Exists(label, provider)) {
                key = CngKey.Open(label, provider);
            } else {
                key = CngKey.Create(CngAlgorithm.Rsa, label, keyParams);
            }
        } catch {
            if (useTpm) {
                provider = new CngProvider("Microsoft Software Key Storage Provider");
                keyParams.Provider = provider;
                if (CngKey.Exists(label, provider)) {
                    key = CngKey.Open(label, provider);
                } else {
                    key = CngKey.Create(CngAlgorithm.Rsa, label, keyParams);
                }
            } else {
                throw;
            }
        }

        using (RSACng rsa = new RSACng(key)) {
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string proofString = "ZTA-CERT-BINDING|CN=" + cn + "|TIME=" + timestamp;
            byte[] dataToSign = Encoding.UTF8.GetBytes(proofString);
            byte[] signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            RSAParameters rsaParams = rsa.ExportParameters(false);

            Hashtable result = new Hashtable();
            result["signature_b64"] = Convert.ToBase64String(signature);
            result["modulus_b64"] = Convert.ToBase64String(rsaParams.Modulus);
            result["exponent_b64"] = Convert.ToBase64String(rsaParams.Exponent);
            result["proof_string"] = proofString;
            result["hw_provider"] = provider.Provider;
            return result;
        }
    }

    public static Hashtable GenerateSoftwareKeyPair(string cn) {
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

            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string proofString = "ZTA-CERT-BINDING|CN=" + cn + "|TIME=" + timestamp;
            byte[] dataToSign = Encoding.UTF8.GetBytes(proofString);
            byte[] signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Hashtable result = new Hashtable();
            result["private_key_pem"] = privPem;
            result["modulus_b64"] = Convert.ToBase64String(p.Modulus);
            result["exponent_b64"] = Convert.ToBase64String(p.Exponent);
            result["proof_string"] = proofString;
            result["signature_b64"] = Convert.ToBase64String(signature);
            return result;
        }
    }

    private static byte[] EncodeInteger(byte[] bytes) {
        int left = 0;
        while (left < bytes.Length && bytes[left] == 0) left++;
        int len = bytes.Length - left;
        if (len == 0) return new byte[] { 0x02, 0x01, 0x00 };

        bool pad = (bytes[left] & 0x80) != 0;
        int datalen = len + (pad ? 1 : 0);

        byte[] lenBytes = EncodeLength(datalen);
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

    private static byte[] EncodeSequence(params byte[][] parts) {
        int totalLen = 0;
        foreach (var p in parts) totalLen += p.Length;
        byte[] lenBytes = EncodeLength(totalLen);
        byte[] res = new byte[1 + lenBytes.Length + totalLen];
        res[0] = 0x30;
        Buffer.BlockCopy(lenBytes, 0, res, 1, lenBytes.Length);
        int writePos = 1 + lenBytes.Length;
        foreach (var p in parts) {
            Buffer.BlockCopy(p, 0, res, writePos, p.Length);
            writePos += p.Length;
        }
        return res;
    }

    private static byte[] EncodeLength(int length) {
        if (length < 128) return new byte[] { (byte)length };
        if (length <= 255) return new byte[] { 0x81, (byte)length };
        return new byte[] { 0x82, (byte)(length >> 8), (byte)(length & 0xff) };
    }

    public static string ExportPublicKeyPem(byte[] modulus, byte[] exponent) {
        byte[] modDer = EncodeInteger(modulus);
        byte[] expDer = EncodeInteger(exponent);
        byte[] rsaPubKeyDer = EncodeSequence(modDer, expDer);

        byte[] bitStringLenBytes = EncodeLength(1 + rsaPubKeyDer.Length);
        byte[] bitStringDer = new byte[1 + bitStringLenBytes.Length + 1 + rsaPubKeyDer.Length];
        bitStringDer[0] = 0x03;
        Buffer.BlockCopy(bitStringLenBytes, 0, bitStringDer, 1, bitStringLenBytes.Length);
        bitStringDer[1 + bitStringLenBytes.Length] = 0x00;
        Buffer.BlockCopy(rsaPubKeyDer, 0, bitStringDer, 2 + bitStringLenBytes.Length, rsaPubKeyDer.Length);

        byte[] algIdDer = new byte[] { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
        byte[] spkiDer = EncodeSequence(algIdDer, bitStringDer);

        string b64 = Convert.ToBase64String(spkiDer, Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN PUBLIC KEY-----\r\n" + b64 + "\r\n-----END PUBLIC KEY-----";
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies "System.Security"
[ZtaCryptoHelper]::BypassSsl()
