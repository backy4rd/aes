using System;

namespace aes {
    class Program {
        static void Main(string[] args) {
            AES aes = new AES("1234567890123456", 128);
            
            string encryptedText = aes.encrypt("some text");
            Console.WriteLine("Encrypted text: " + encryptedText);
            
            string decryptedText = aes.decrypt(encryptedText);
            Console.WriteLine("Decrypted Text: " + decryptedText);
        }
    }
}
