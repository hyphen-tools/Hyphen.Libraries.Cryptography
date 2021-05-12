using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Hyphen.Libraries.Cryptography.Encryption.SymmetricEncryption
{
    public class TripleDES
    {
        public static readonly System.Text.Encoding Encoder = System.Text.Encoding.UTF8;

        public static string Encrypt(string plainText, string key)
        {
            var des = CreateDes(key);
            var ct = des.CreateEncryptor();
            var input = System.Text.Encoding.UTF8.GetBytes(plainText);
            var output = ct.TransformFinalBlock(input, 0, input.Length);
            return Convert.ToBase64String(output);
        }

        public static string Decrypt(string cypherText, string key)
        {
            var des = CreateDes(key);
            var ct = des.CreateDecryptor();
            var input = Convert.FromBase64String(cypherText);
            var output = ct.TransformFinalBlock(input, 0, input.Length);
            return System.Text.Encoding.UTF8.GetString(output);
        }

        public static System.Security.Cryptography.TripleDES CreateDes(string key)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            System.Security.Cryptography.TripleDES des = new TripleDESCryptoServiceProvider();
            var desKey = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(key));
            des.Key = desKey;
            des.IV = new byte[des.BlockSize / 8];
            des.Padding = PaddingMode.PKCS7;
            des.Mode = CipherMode.ECB;
            return des;
        }
    }
}
