using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Hyphen.Libraries.Cryptography.Encryption.AsymmetricEncryption
{
    public class RSA
    {
        public static byte[] Encrypt(string publicKey, string text)
        {
            // Convert the text to an array of bytes   
            UTF8Encoding byteConverter = new UTF8Encoding();
            byte[] dataToEncrypt = byteConverter.GetBytes(text);

            // Create a byte array to store the encrypted data in it   
            byte[] encryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Set the rsa pulic key   
                rsa.FromXmlString(publicKey);

                // Encrypt the data and store it in the encyptedData Array   
                encryptedData = rsa.Encrypt(dataToEncrypt, false);
            }
            // Save the encypted data array into a file   
            return encryptedData;
        }

        // Method to decrypt the data withing a specific file using a RSA algorithm private key   
        public static string Decrypt(string privateKey, string encryptedText)
        {
            // read the encrypted bytes from the file   
            byte[] dataToDecrypt = System.Text.Encoding.UTF8.GetBytes(encryptedText);

            // Create an array to store the decrypted data in it   
            byte[] decryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Set the private key of the algorithm   
                rsa.FromXmlString(privateKey);
                decryptedData = rsa.Decrypt(dataToDecrypt, false);
            }

            // Get the string value from the decryptedData byte array   
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            return byteConverter.GetString(decryptedData);
        }
    }
}
