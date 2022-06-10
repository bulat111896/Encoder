using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace BestEncoder
{
    public class Encoder
    {
        public static string pass = "b7c9d7190f17b46847852cb0ca6e826edac8168a8035f1839f77e732890ba93a";
        public static string key1 = "a40808ec481e841008f8c5804645211q";
        public static string key2 = "2a2542f9e61a9a1w";
        public static int iterations = 21;

        public static string Encode(string text)
        {
            byte[] cipherTextBytes;
            using (ICryptoTransform encryptor = new RijndaelManaged().CreateEncryptor(new PasswordDeriveBytes(pass, Encoding.ASCII.GetBytes(key1), "SHA1", iterations).GetBytes(32), Encoding.ASCII.GetBytes(key2)))
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(Encoding.UTF8.GetBytes(text), 0, text.Length);
                        cryptoStream.FlushFinalBlock();
                        cipherTextBytes = memStream.ToArray();
                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }
            return Convert.ToBase64String(cipherTextBytes);
        }

        public static string Decode(string text)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(text);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            int byteCount = 0;
            using (ICryptoTransform decryptor = new RijndaelManaged().CreateDecryptor(new PasswordDeriveBytes(pass, Encoding.ASCII.GetBytes(key1), "SHA1", iterations).GetBytes(32), Encoding.ASCII.GetBytes(key2)))
            {
                using (MemoryStream mSt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(mSt, decryptor, CryptoStreamMode.Read))
                    {
                        byteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                        mSt.Close();
                        cryptoStream.Close();
                    }
                }
            }
            return Encoding.UTF8.GetString(plainTextBytes, 0, byteCount);
        }
    }
}