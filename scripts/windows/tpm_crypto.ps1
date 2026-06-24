# tpm_crypto.ps1 - C# type definitions for crypto operations

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
    Add-Type -TypeDefinition '
        using System;
        using System.Net;
        using System.Security.Cryptography;
        using System.Security.Cryptography.X509Certificates;
        using System.Text;
        using System.Collections;

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
    '
    [SSLBypass]::Bypass()
} catch {
    [SSLBypass]::Bypass()
}
