using System.Security.Cryptography;
using System.Text;
using System;
using AESManaged.Models;

namespace AESManaged.Services
{
    public static class AesService
    {
        public static string Encrypt(string textToEncrypt, ApiTokenModel model)
        {
            try
            {
                byte[] iv = new byte[16];
                Array.Clear(iv, 0, iv.Length);
                //  var ivspec = new IvParameterSpec(iv);

                var factory = new Rfc2898DeriveBytes(model.ClientSecret, Encoding.UTF8.GetBytes(model.Salt), 65536, HashAlgorithmName.SHA256);
                var secretKey = new AesManaged().CreateEncryptor(factory.GetBytes(32), iv);

                var encrypted = secretKey.TransformFinalBlock(Encoding.UTF8.GetBytes(textToEncrypt), 0, textToEncrypt.Length);
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception e)
            {
                return "Error while decrypting: " + e;
            }
        }

        public static string Decrypt(string textToDecrypt, ApiTokenModel model)
        {
            try
            {
                byte[] iv = new byte[16];
                Array.Clear(iv, 0, iv.Length);
                // var ivspec = new IvParameterSpec(iv);

                var factory = new Rfc2898DeriveBytes(model.ClientSecret, Encoding.UTF8.GetBytes(model.Salt), 65536, HashAlgorithmName.SHA256);
                var secretKey = new AesManaged().CreateDecryptor(factory.GetBytes(32), iv);

                var decrypted = secretKey.TransformFinalBlock(Convert.FromBase64String(textToDecrypt), 0, Convert.FromBase64String(textToDecrypt).Length);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception e)
            {
                return "Error while decrypting: " + e;
            }
        }
    }
}
