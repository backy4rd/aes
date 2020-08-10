using System;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace aes {
    public class AES {
        private static Encoding ASCII = Encoding.ASCII;
        private readonly int type;
        private readonly List<byte[,]> roundKeys;

        private static readonly byte[,] S_BOX = new byte[16, 16] {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };
        
        private static readonly byte[,] INV_S_BOX = new byte[16, 16] {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        private static readonly byte[,] MIX_MATRIX = new byte[4, 4] {
            { 2, 3, 1, 1 },
            { 1, 2, 3, 1 },
            { 1, 1, 2, 3 },
            { 3, 1, 1, 2 }
        };
        
        private static readonly byte[,] INV_MIX_MATRIX = new byte[4, 4] {
            { 14, 11, 13, 9 },
            { 9, 14, 11, 13 },
            { 13, 9, 14, 11 },
            { 11, 13, 9, 14 }
        };
        
        private static readonly List<byte[]> R_CON = new List<byte[]> {
            new byte[] { 1, 0, 0, 0 },
            new byte[] { 2, 0, 0, 0 },
            new byte[] { 4, 0, 0, 0 },
            new byte[] { 8, 0, 0, 0 },
            new byte[] { 16, 0, 0, 0 },
            new byte[] { 32, 0, 0, 0 },
            new byte[] { 64, 0, 0, 0 },
            new byte[] { 128, 0, 0, 0 },
            new byte[] { 27, 0, 0, 0 },
            new byte[] { 54, 0, 0, 0 },
        };

        private int round {
            get {
                return type switch {
                    128 => 9,
                    192 => 11,
                    _ => 13
                };
            }
        }

        public AES(string secretKey, int type) {
            if (type != 128 && type != 192 && type != 256) {
                throw new Exception("invalid aes type");
            }
            if (type / 8.0 != secretKey.Length) {
                throw new Exception("invalid key");
            }

            this.type = type;
            roundKeys = genRoundKeys(secretKey);
        }
        
        private List<byte[,]> genRoundKeys(string secretKey) {
            List<byte[,]> listKeys = new List<byte[,]>();
            byte[,] firstKeyRound = genBlock(ASCII.GetBytes(secretKey));
            listKeys.Add(firstKeyRound);

            for (int i = 0; i < R_CON.Count; i++) {
                byte[,] prevKey = listKeys[^1];
                byte[] firstCol = new byte[4] { prevKey[0,3], prevKey[1,3], prevKey[2,3], prevKey[3,3] };
                // shift Column
                byte temp = firstCol[0];
                firstCol[0] = firstCol[1];
                firstCol[1] = firstCol[2];
                firstCol[2] = firstCol[3];
                firstCol[3] = temp;
                
                // sub byte
                for (int j = 0; j < 4; j++) {
                    int si = firstCol[j] >> 4;
                    int sj = firstCol[j] & 15;
                    firstCol[j] = S_BOX[si,sj];
                }

                // xor
                firstCol[0] = (byte)(prevKey[0,0] ^ firstCol[0] ^ R_CON[i][0]);
                firstCol[1] = (byte)(prevKey[1,0] ^ firstCol[1] ^ R_CON[i][1]);
                firstCol[2] = (byte)(prevKey[2,0] ^ firstCol[2] ^ R_CON[i][2]);
                firstCol[3] = (byte)(prevKey[3,0] ^ firstCol[3] ^ R_CON[i][3]);
                
                // generate the rest
                byte[,] key = new byte[4,4];
                key[0,0] = firstCol[0];
                key[1,0] = firstCol[1];
                key[2,0] = firstCol[2];
                key[3,0] = firstCol[3];
                
                for (int j = 1; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        key[k, j] = (byte)(key[k,j - 1] ^ prevKey[k,j]);
                    }
                }
                
                listKeys.Add(key);
            }
            return listKeys;
        }

        public string encrypt(string data) {
            byte[] bytes = ASCII.GetBytes(data);
            byte[] encrypted = new byte[data.Length + (15 - (data.Length - 1) % 16)];

            for (int curLength = 0; curLength < data.Length; curLength += 16) {
                byte[] chunk = encryptChunk(bytes.Skip(curLength).Take(16).ToArray());
                Array.Copy(chunk, 0, encrypted, curLength, 16);
            }
            
            return Convert.ToBase64String(encrypted);
        }
        
        public string decrypt(string encryptedText) {
            byte[] encrypted = Convert.FromBase64String(encryptedText);
            byte[] decrypted = new byte[encrypted.Length];
            
            for (int curLength = 0; curLength < encrypted.Length; curLength += 16) {
                byte[] chunk = decryptChunk(encrypted.Skip(curLength).Take(16).ToArray());
                Array.Copy(chunk, 0, decrypted, curLength, 16);
            }

            // trim additional byte "0x00";
            int endOfText = decrypted.Length - 1;
            while (decrypted[endOfText] == 0) endOfText--;

            return ASCII.GetString(decrypted.Take(endOfText + 1).ToArray());
        }

        private byte[] encryptChunk(byte[] data) {
            byte[,] block = genBlock(data);

            addRoundKey(block, roundKeys[0]);
            for (int i = 1; i < round; i++) {
                subBytes(block, S_BOX);
                shiftRows(block);
                mixColumns(block, MIX_MATRIX);
                addRoundKey(block, roundKeys[i]);
            }
            subBytes(block, S_BOX);
            shiftRows(block);
            addRoundKey(block, roundKeys[round]);

            return flattenBlock(block);
        }

        private byte[] decryptChunk(byte[] encryptedChunk) {
            byte[,] block = genBlock(encryptedChunk);
            
            addRoundKey(block, roundKeys[round]);
            invShiftRows(block);
            subBytes(block, INV_S_BOX);
            for (int i = round - 1; i > 0; i--) {
                addRoundKey(block, roundKeys[i]);
                mixColumns(block, INV_MIX_MATRIX);
                invShiftRows(block);
                subBytes(block, INV_S_BOX);
            }
            addRoundKey(block, roundKeys[0]);

            return flattenBlock(block);
        }

        private static void addRoundKey(byte[,] block, byte[,] roundKey) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    block[i, j] = (byte)(block[i, j] ^ roundKey[i, j]);
                }
            }
        }

        private static void subBytes(byte[,] block, byte[,] sBox) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    int si = block[i, j] >> 4;
                    int sj = block[i, j] & 15;
                    block[i, j] = sBox[si, sj];
                }
            }
        }

        private static void shiftRows(byte[,] block) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < i; j++) {
                    byte temp = block[i, 0];
                    block[i,0] = block[i,1];
                    block[i,1] = block[i,2];
                    block[i,2] = block[i,3];
                    block[i,3] = temp;
                }
            }
        }

        private static void mixColumns(byte[,] block, byte[,] mixMatrix) {
            byte[,] temp = block.Clone() as byte[,];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    block[i, j] = (byte)(
                        mix(temp[0, j], mixMatrix[i, 0]) ^
                        mix(temp[1, j], mixMatrix[i, 1]) ^
                        mix(temp[2, j], mixMatrix[i, 2]) ^
                        mix(temp[3, j], mixMatrix[i, 3])
                    );
                }
            }
        }

        private static void invShiftRows(byte[,] block) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < i; j++) {
                    byte temp = block[i, 3];
                    block[i,3] = block[i,2];
                    block[i,2] = block[i,1];
                    block[i,1] = block[i,0];
                    block[i,0] = temp;
                }
            }
        }

        /*
        private static void printBlock(byte[,] block) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    Console.Write("{0,3:x}", block[i, j]);
                }
                Console.WriteLine();
            }
        }
        */
        
        private static byte mix(byte a, int b) {
            switch (b) {
                case 1: return a;
                case 2:
                    if (a * b > 0xff) {
                        return (byte)((a * b) ^ 0x1b);
                    }
                    return (byte)(a * b);
                case 3:
                    if (a * 2 > 0xff) {
                        return (byte)((a * 2) ^ 0x1b ^ a);
                    }
                    return (byte)((a * 2) ^ a);
                case 9:
                    // (((a x 2) x 2) x 2) + x
                    return (byte)(mix(mix(mix(a, 2), 2), 2) ^ a);
                case 11:
                    // ((((a × 2) × 2) + a) × 2) + a
                    return (byte)(mix((byte)(mix(mix(a, 2), 2) ^ a), 2) ^ a);
                case 13:
                    // ((((a × 2) + a) × 2) × 2) + a
                    return (byte)(mix(mix((byte)(mix(a, 2) ^ a), 2), 2) ^ a);
                case 14:
                    // ((((a × 2) + a) × 2) + a) x 2 
                    return mix((byte)(mix((byte)(mix(a, 2) ^ a), 2) ^ a), 2);
                default: return 0;
            }
        }

        private static byte[,] genBlock(byte[] data) {
            if (data.Length > 16) {
                throw new Exception("invalid data length");
            }

            if (data.Length < 16) {
                var temp = new byte[16];
                Array.Copy(data, temp, data.Length);
                Array.Fill<byte>(temp, 0, data.Length, 16 - data.Length);

                data = temp;
            }

            return new byte[4, 4] {
                { data[0], data[4], data[8], data[12] },
                { data[1], data[5], data[9], data[13] },
                { data[2], data[6], data[10], data[14] },
                { data[3], data[7], data[11], data[15] },
            };
        }

        private static byte[] flattenBlock(byte[,] block) {
            return new byte[16] {
                block[0,0], block[1,0], block[2,0], block[3,0],
                block[0,1], block[1,1], block[2,1], block[3,1],
                block[0,2], block[1,2], block[2,2], block[3,2],
                block[0,3], block[1,3], block[2,3], block[3,3],
            };
        }
    }
}