/*
   Copyright 2021 Nils Kopal, CrypTool Team

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
using System;
using System.Numerics;
using System.Text;

namespace AES
{
    /// <summary>
    /// "Crazy AES-like cipher" that only works on text data (Latin Alphabet A-Z)
    /// The structure of the cipher is the same structure of AES with some changes:
    /// - The S-Box is a bigram substitution (randomly created fixed table) instead of a byte-based substitution
    /// - XOR-ing the keys is replaced by a Vigenère cipher (just adds and subtracts the roundkeys)
    /// - ShiftRows is exactly the same as with original AES
    /// - MixColumns is replaced by a Hill cipher (still matrix multiplication :-)), we use the "original" matrix for encryption
    /// - KeyExpansion is exchanged completely (uses ShiftRows, MixColumns, and round constants from A-Z to expand the key)
    /// - We also perform 10 rounds like AES-128
    /// - We define the mapping from letters to numbers as: A=0, B=1, C=2, ..., Z=25
    /// </summary>
    public class TextAES
    {
        //Hint: if you want to change the alphabet, you also have to change:
        //- The bigram substitution (S-Box and its inverse)
        //  since the S-Box is built on a 26x26 letter grid and only contains numbers between 0 and 26*26
        //- The hill cipher
        //  since the matrices are built for a 26-letter alphabet (from 0 to 25)
        public const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        #region S-Box

        public static int[] SBox = new int[]
        {
            019, 534, 428, 602, 545, 271, 675, 490, 014, 606, 471, 621, 637, 234, 414, 299, 180, 669, 221, 127, 636, 371, 482, 034, 648, 487,
            440, 336, 508, 472, 370, 069, 563, 105, 114, 656, 539, 311, 661, 259, 048, 530, 660, 150, 202, 181, 191, 139, 627, 231, 655, 323,
            214, 164, 052, 642, 349, 535, 320, 128, 448, 454, 625, 501, 145, 222, 338, 102, 445, 667, 168, 084, 142, 555, 075, 546, 481, 646,
            594, 213, 192, 092, 162, 495, 079, 367, 601, 016, 499, 518, 671, 613, 094, 528, 064, 407, 289, 657, 189, 592, 558, 233, 398, 649,
            268, 266, 474, 381, 303, 511, 264, 172, 054, 479, 163, 569, 504, 658, 091, 295, 196, 122, 347, 104, 024, 316, 375, 260, 182, 600,
            252, 106, 604, 018, 515, 135, 157, 281, 622, 548, 588, 071, 470, 411, 331, 599, 028, 350, 073, 346, 496, 255, 304, 136, 580, 126,
            099, 633, 146, 251, 087, 537, 639, 452, 361, 653, 095, 390, 169, 460, 582, 373, 360, 185, 166, 348, 368, 246, 227, 020, 590, 086,
            467, 207, 378, 219, 098, 125, 629, 355, 391, 570, 244, 449, 170, 549, 240, 206, 193, 359, 210, 177, 663, 547, 220, 248, 129, 195,
            261, 670, 280, 276, 041, 394, 208, 090, 556, 258, 080, 282, 573, 560, 620, 319, 632, 083, 292, 559, 587, 116, 332, 364, 132, 302,
            575, 513, 212, 584, 245, 030, 334, 353, 115, 526, 585, 198, 081, 458, 269, 461, 120, 579, 450, 437, 050, 451, 298, 309, 345, 341,
            328, 242, 026, 008, 117, 645, 243, 293, 031, 567, 538, 497, 176, 507, 553, 229, 023, 286, 429, 056, 533, 226, 322, 060, 357, 400,
            025, 138, 647, 045, 007, 611, 469, 510, 002, 595, 294, 167, 641, 541, 358, 065, 576, 477, 062, 517, 211, 593, 006, 431, 134, 354,
            096, 532, 313, 197, 287, 029, 343, 608, 425, 296, 239, 557, 404, 199, 388, 422, 160, 230, 275, 443, 652, 369, 492, 610, 509, 254,
            616, 043, 640, 310, 137, 188, 093, 224, 317, 638, 284, 173, 238, 290, 027, 039, 175, 078, 036, 152, 659, 183, 418, 352, 473, 484,
            200, 257, 077, 082, 416, 300, 044, 551, 536, 525, 617, 419, 053, 318, 512, 237, 384, 111, 119, 483, 046, 148, 589, 335, 506, 421,
            498, 397, 133, 396, 315, 118, 088, 550, 156, 438, 485, 634, 235, 051, 201, 514, 522, 596, 424, 253, 505, 329, 430, 141, 305, 392,
            612, 615, 403, 395, 565, 204, 110, 527, 475, 263, 165, 055, 415, 426, 402, 383, 278, 586, 420, 457, 568, 256, 441, 628, 609, 324,
            154, 171, 184, 283, 465, 666, 159, 476, 130, 070, 597, 462, 520, 109, 480, 374, 326, 650, 668, 247, 015, 151, 572, 074, 651, 066,
            032, 042, 654, 265, 624, 186, 491, 399, 344, 674, 339, 493, 578, 571, 488, 502, 153, 455, 022, 552, 321, 017, 466, 463, 072, 312,
            236, 618, 519, 035, 272, 061, 144, 010, 000, 009, 673, 306, 529, 623, 643, 500, 140, 598, 389, 442, 447, 187, 432, 314, 591, 581,
            147, 377, 085, 037, 544, 250, 089, 521, 459, 047, 542, 635, 004, 249, 273, 386, 342, 270, 554, 385, 262, 178, 435, 446, 058, 033,
            228, 174, 340, 190, 664, 218, 038, 307, 619, 444, 413, 356, 291, 209, 179, 325, 564, 566, 453, 216, 516, 100, 101, 279, 405, 131,
            001, 267, 059, 503, 301, 523, 410, 366, 494, 285, 330, 626, 003, 365, 223, 540, 379, 406, 124, 205, 433, 362, 665, 351, 121, 194,
            644, 489, 417, 161, 486, 113, 012, 241, 011, 274, 288, 143, 297, 583, 603, 155, 605, 308, 103, 631, 149, 327, 123, 376, 277, 614,
            423, 456, 393, 013, 577, 363, 068, 005, 543, 439, 562, 531, 630, 468, 436, 158, 097, 372, 337, 057, 434, 574, 049, 232, 409, 063,
            108, 203, 217, 382, 333, 380, 067, 524, 607, 464, 427, 112, 021, 662, 672, 107, 561, 040, 408, 412, 401, 225, 215, 387, 076, 478
        };

        public static int[] SBoxInverse = new int[]
        {
            502, 572, 294, 584, 532, 631, 308, 290, 263, 503, 501, 606, 604, 627, 008, 462, 087, 489, 133, 000, 179, 662, 486, 276, 124, 286,
            262, 352, 146, 317, 239, 268, 468, 545, 023, 497, 356, 523, 552, 353, 667, 212, 469, 339, 370, 289, 384, 529, 040, 646, 254, 403,
            054, 376, 112, 427, 279, 643, 544, 574, 283, 499, 304, 649, 094, 301, 467, 656, 630, 031, 451, 141, 492, 148, 465, 074, 674, 366,
            355, 084, 218, 246, 367, 225, 071, 522, 181, 160, 396, 526, 215, 118, 081, 344, 092, 166, 312, 640, 186, 156, 567, 568, 067, 616,
            123, 033, 131, 665, 650, 455, 422, 381, 661, 603, 034, 242, 229, 264, 395, 382, 250, 596, 121, 620, 590, 187, 155, 019, 059, 206,
            450, 571, 232, 392, 310, 135, 153, 342, 287, 047, 510, 413, 072, 609, 500, 064, 158, 520, 385, 618, 043, 463, 357, 484, 442, 613,
            398, 136, 639, 448, 328, 601, 082, 114, 053, 426, 174, 297, 070, 168, 194, 443, 111, 349, 547, 354, 272, 201, 541, 560, 016, 045,
            128, 359, 444, 173, 473, 515, 343, 098, 549, 046, 080, 198, 597, 207, 120, 315, 245, 325, 364, 404, 044, 651, 421, 591, 197, 183,
            214, 559, 200, 306, 236, 079, 052, 672, 565, 652, 551, 185, 204, 018, 065, 586, 345, 671, 281, 178, 546, 275, 329, 049, 647, 101,
            013, 402, 494, 379, 350, 322, 196, 605, 261, 266, 192, 238, 177, 461, 205, 533, 525, 159, 130, 409, 337, 151, 437, 365, 217, 039,
            127, 208, 540, 425, 110, 471, 105, 573, 104, 248, 537, 005, 498, 534, 607, 330, 211, 622, 432, 569, 210, 137, 219, 445, 348, 581,
            277, 316, 608, 096, 351, 558, 226, 267, 296, 119, 321, 610, 256, 015, 369, 576, 233, 108, 152, 414, 505, 553, 615, 257, 341, 037,
            493, 314, 517, 394, 125, 346, 377, 223, 058, 488, 282, 051, 441, 561, 458, 619, 260, 411, 582, 144, 230, 654, 240, 387, 027, 642,
            066, 478, 548, 259, 536, 318, 476, 258, 149, 122, 175, 056, 147, 595, 361, 241, 311, 189, 557, 284, 300, 199, 172, 164, 593, 629,
            231, 585, 579, 085, 176, 333, 030, 021, 641, 171, 457, 126, 621, 521, 184, 588, 655, 107, 653, 431, 380, 539, 535, 673, 326, 512,
            167, 190, 415, 626, 213, 419, 393, 391, 102, 475, 285, 670, 430, 418, 324, 570, 589, 095, 668, 648, 578, 143, 669, 556, 014, 428,
            368, 600, 360, 375, 434, 389, 327, 624, 408, 320, 429, 660, 002, 278, 412, 309, 516, 592, 644, 542, 638, 253, 399, 633, 026, 438,
            513, 331, 555, 068, 543, 514, 060, 193, 252, 255, 163, 564, 061, 485, 625, 435, 247, 528, 169, 249, 453, 491, 659, 446, 490, 182,
            637, 292, 142, 010, 029, 362, 106, 424, 449, 303, 675, 113, 456, 076, 022, 383, 363, 400, 602, 025, 482, 599, 007, 474, 334, 479,
            580, 083, 150, 271, 390, 088, 509, 063, 483, 575, 116, 410, 388, 273, 028, 336, 293, 109, 378, 235, 405, 134, 566, 305, 089, 496,
            454, 527, 406, 577, 657, 373, 243, 423, 093, 506, 041, 635, 313, 280, 001, 057, 372, 161, 270, 036, 587, 299, 530, 632, 524, 004,
            075, 203, 139, 195, 397, 371, 487, 274, 538, 073, 216, 323, 100, 227, 221, 666, 634, 032, 562, 420, 563, 269, 436, 115, 191, 481,
            464, 220, 645, 234, 302, 628, 480, 251, 154, 519, 170, 611, 237, 244, 433, 228, 140, 386, 180, 518, 099, 307, 078, 295, 407, 452,
            511, 145, 129, 086, 003, 612, 132, 614, 009, 658, 319, 440, 335, 291, 416, 091, 623, 417, 338, 374, 495, 554, 222, 011, 138, 507,
            472, 062, 583, 048, 439, 188, 636, 617, 224, 157, 401, 531, 020, 012, 347, 162, 340, 298, 055, 508, 598, 265, 077, 288, 024, 103,
            459, 466, 332, 165, 470, 050, 035, 097, 117, 358, 042, 038, 663, 202, 550, 594, 447, 069, 460, 017, 209, 090, 664, 504, 477, 006
        };
        #endregion

        #region Hill cipher matrices

        public static int[] HillCipherMatrix = new int[]
        {
             02, 03, 01, 01,
             01, 02, 03, 01,
             01, 01, 02, 03,
             03, 01, 01, 02,
        };

       public static int[] HillCipherMatrixInverse = new int[]
       {
             14, 09, 19, 25,
             25, 14, 09, 19,
             19, 25, 14, 09,
             09, 19, 25, 14,
       };

        #endregion

        #region Helper functions

        public static int Mod(int number, int mod)
        {
            return ((number % mod) + mod) % mod;
        }
    
        public static string MapNumbersIntoTextSpace(int[] numbers, string alphabet)
        {
            var builder = new StringBuilder();
            foreach (var i in numbers)
            {
                builder.Append(alphabet[i]);
            }
            return builder.ToString();
        }
       
        public static int[] MapTextIntoNumberSpace(string text, string alphabet)
        {
            var numbers = new int[text.Length];
            var position = 0;
            foreach (var c in text)
            {
                numbers[position] = alphabet.IndexOf(c);
                position++;
            }
            return numbers;
        }

        public static void GenerateSBoxAndInverse()
        {
            var sbox = new int[ALPHABET.Length * ALPHABET.Length];
            var sbox_inverse = new int[ALPHABET.Length * ALPHABET.Length];

            //fill S-Box with numbers 
            for (var i = 0; i < sbox.Length; i++)
            {
                sbox[i] = i;
            }

            //shuffle S-Box
            var random = new Random();
            var n = sbox.Length;
            while (n > 1)
            {
                int k = random.Next(n--);
                var temp = sbox[n];
                sbox[n] = sbox[k];
                sbox[k] = temp;
            }

            //create inverse s-box
            for (var i = 0; i < sbox.Length; i++)
            {
                sbox_inverse[sbox[i]] = i;
            }

            //print out S-Box
            Console.WriteLine("S-Box:");
            var counter = 0;
            foreach (var i in sbox)
            {
                if (i < 10)
                {
                    Console.Write("00");
                }
                else if (i < 100)
                {
                    Console.Write("0");
                }
                Console.Write(i + " ");
                counter++;
                if (counter == ALPHABET.Length)
                {
                    Console.WriteLine();
                    counter = 0;
                }
            }

            //print out S-Box inverse
            Console.WriteLine("S-Box inverse:");
            counter = 0;
            foreach (var i in sbox_inverse)
            {
                if (i < 10)
                {
                    Console.Write("00");
                }
                else if (i < 100)
                {
                    Console.Write("0");
                }
                Console.Write(i + " ");
                counter++;
                if (counter == ALPHABET.Length)
                {
                    Console.WriteLine();
                    counter = 0;
                }
            }
        }

        public string GenerateRandomTextKey()
        {
            var builder = new StringBuilder();
            var random = new Random();

            for (int i = 0; i < 16; i++)
            {
                builder.Append(ALPHABET[random.Next(0, ALPHABET.Length - 1)]);
            }
            return builder.ToString();

        }

        #endregion

        #region TextAES primitives

        public void AddRoundKey(int[] data, int[] roundkey)
        {
            for(var i = 0; i < data.Length; i++)
            {
                data[i] = Mod(data[i] + roundkey[i], ALPHABET.Length);
            }
        }

        public void SubtractRoundKey(int[] data, int[] roundkey)
        {
            for (var i = 0; i < data.Length; i++)
            {
                data[i] = Mod(data[i] - roundkey[i], ALPHABET.Length);
            }
        }

        public void PrintSbox(int[] sbox)
        {
            for(int y = 0; y < 26; y++)
            {
                for (int x = 0; x < 26; x++)
                {
                    int offset = y * 26 + x;
                    int[] value = new int[] { sbox[offset] / 26, sbox[offset] % 26};
                    Console.Write(MapNumbersIntoTextSpace(value, ALPHABET) + " ");                    
                }
                Console.WriteLine();
            }            
        }

        public int[] SubBigrams(int[] data)
        {
            for (int i = 0; i < data.Length; i += 2)
            {
                var sub = SubBigram(new int[] { data[i], data[i + 1] });
                data[i] = sub[0];
                data[i + 1] = sub[1];
            }
            return data;
            int[] SubBigram(int[] bigram)
            {
                var offset = bigram[0] * ALPHABET.Length + bigram[1];
                var number = SBox[offset];
                return new int[] { number / ALPHABET.Length, number % ALPHABET.Length };
            }
        }

        public int[] SubBigramsInverse(int[] data)
        {
            for (int i = 0; i < data.Length; i += 2)
            {
                var sub = SubBigram(new int[] { data[i], data[i + 1]  });
                data[i] = sub[0];
                data[i + 1] = sub[1];
            }
            return data;
            int[] SubBigram(int[] bigram)
            {
                var offset = bigram[0] * ALPHABET.Length + bigram[1];
                var number = SBoxInverse[offset];
                return new int[] { number / ALPHABET.Length, number % ALPHABET.Length };
            }
        }
        
        public void ShiftRows(int[] data)
        {
            // 0   4   8  12
            // 1   5   9  13 <- 1 letter to left circular shift
            // 2   6  10  14 <- 2 letter to left circular shift
            // 3   7  11  15 <- 3 letter to left circular shift

            int swap;

            //1. row: remains unshifted (do nothing)

            //2. row: shift one to the left
            swap = data[1];
            data[1] = data[5];
            data[5] = data[9];
            data[9] = data[13];
            data[13] = swap;

            //3. row: shift two to the left = exchange every 2nd
            swap = data[2];
            data[2] = data[10];
            data[10] = swap;
            swap = data[6];
            data[6] = data[14];
            data[14] = swap;

            //4. row: shift three to the left = shift to the right
            swap = data[15];
            data[15] = data[11];
            data[11] = data[7];
            data[7] = data[3];
            data[3] = swap;
        }
       
        public void ShiftRowsInverse(int[] data)
        {
            // 0   4   8  12
            // 1   5   9  13 <- 1 letter to right circular shift
            // 2   6  10  14 <- 2 letter to right circular shift
            // 3   7  11  15 <- 3 letter to right circular shift

            int swap;

            //1. row: remains unshifted (do nothing)

            //2. row: shift one to the right
            swap = data[13];
            data[13] = data[9];
            data[9] = data[5];
            data[5] = data[1];
            data[1] = swap;

            //3. row: shift two to the right = exchange every 2nd
            swap = data[2];
            data[2] = data[10];
            data[10] = swap;
            swap = data[6];
            data[6] = data[14];
            data[14] = swap;

            //4. row: shift three to the right = shift to the left
            swap = data[3];
            data[3] = data[7];
            data[7] = data[11];
            data[11] = data[15];
            data[15] = swap;
        }

        public void MixColumns(int[] data)
        {
            BigInteger b0, b1, b2, b3;

            // 0   4   8  12
            // 1   5   9  13
            // 2   6  10  14
            // 3   7  11  15

            //Matrix multiplication (hill cipher encryption) is performed for each column vector
            for (var i = 0; i < 16; i += 4)
            {
                b0 = data[i + 0];
                b1 = data[i + 1];
                b2 = data[i + 2];
                b3 = data[i + 3];
                
                data[i + 0] = (int)(HillCipherMatrix[0] * b0 + HillCipherMatrix[4] * b1 + HillCipherMatrix[8] * b2 + HillCipherMatrix[12] * b3) % ALPHABET.Length;
                data[i + 1] = (int)(HillCipherMatrix[1] * b0 + HillCipherMatrix[5] * b1 + HillCipherMatrix[9] * b2 + HillCipherMatrix[13] * b3) % ALPHABET.Length;
                data[i + 2] = (int)(HillCipherMatrix[2] * b0 + HillCipherMatrix[6] * b1 + HillCipherMatrix[10] * b2 + HillCipherMatrix[14] * b3) % ALPHABET.Length;
                data[i + 3] = (int)(HillCipherMatrix[3] * b0 + HillCipherMatrix[7] * b1 + HillCipherMatrix[11] * b2 + HillCipherMatrix[15] * b3) % ALPHABET.Length;
            }
        }

        public void MixColumnsInverse(int[] data)
        {
            BigInteger b0, b1, b2, b3;

            // 0   4   8  12
            // 1   5   9  13
            // 2   6  10  14
            // 3   7  11  15

            //Matrix multiplication (hill cipher decryption) is performed for each column vector
            for (var i = 0; i < 16; i += 4)
            {
                b0 = data[i + 0];
                b1 = data[i + 1];
                b2 = data[i + 2];
                b3 = data[i + 3];

                data[i + 0] = (int)(HillCipherMatrixInverse[0] * b0 + HillCipherMatrixInverse[4] * b1 + HillCipherMatrixInverse[8] * b2 + HillCipherMatrixInverse[12] * b3) % ALPHABET.Length;
                data[i + 1] = (int)(HillCipherMatrixInverse[1] * b0 + HillCipherMatrixInverse[5] * b1 + HillCipherMatrixInverse[9] * b2 + HillCipherMatrixInverse[13] * b3) % ALPHABET.Length;
                data[i + 2] = (int)(HillCipherMatrixInverse[2] * b0 + HillCipherMatrixInverse[6] * b1 + HillCipherMatrixInverse[10] * b2 + HillCipherMatrixInverse[14] * b3) % ALPHABET.Length;
                data[i + 3] = (int)(HillCipherMatrixInverse[3] * b0 + HillCipherMatrixInverse[7] * b1 + HillCipherMatrixInverse[11] * b2 + HillCipherMatrixInverse[15] * b3) % ALPHABET.Length;
            }
        }

        #endregion

        #region TextAES key schedule       

        /// <summary>
        /// Implementation of TextAES key expansion mainly based on https://en.wikipedia.org/wiki/AES_key_schedule
        /// Returns all round keys in one integer array
        /// </summary>
        /// <param name="K"></param>
        /// <param name="R"></param>
        /// <returns></returns>
        public int[] KeyExpansion(int[] K, int R)
        {
            var N = K.Length / 4;
            var W = new int[4 * 4 * R];

            for (int i = 0; i < 4 * R; i++)
            {
                if (i < N)
                {
                    SetWord(W, GetWord(K, i), i);
                }
                else if (i >= N && i % N == 0)
                {
                    var word = Add(GetWord(W, i - N), SubWord(RotWord(GetWord(W, i - 1))));
                    word = Add(word, rcon(i / N));
                    SetWord(W, word, i);
                }
                else if (i >= N && N > 6 && i % N == 4)
                {
                    var word = Add(GetWord(W, i - N), SubWord(GetWord(W, i - 1)));
                    SetWord(W, word, i);
                }
                else
                {
                    var word = Add(GetWord(W, i - N), GetWord(W, i - 1));
                    SetWord(W, word, i);
                }
            }

            return W;

            /// AES round constants; here we just take a letter from the alphabet
            int[] rcon(int i)
            {
                // we have: A,B,C,D...,Z,A,B,C,D,...
                return new int[] { Mod(i, ALPHABET.Length), 0x00, 0x00, 0x00 };
            }

            ///Extract a 4 letter word from the given offset
            int[] GetWord(int[] data, int offset)
            {
                var word = new int[4];
                word[0] = data[offset * 4 + 0];
                word[1] = data[offset * 4 + 1];
                word[2] = data[offset * 4 + 2];
                word[3] = data[offset * 4 + 3];
                return word;
            }

            ///Set a 4 letter word at the given offset
            void SetWord(int[] data, int[] word, int offset)
            {
                data[offset * 4 + 0] = word[0];
                data[offset * 4 + 1] = word[1];
                data[offset * 4 + 2] = word[2];
                data[offset * 4 + 3] = word[3];
            }

            ///Adds two given 4 letters words MOD alphabet length
            int[] Add(int[] w1, int[] w2)
            {
                var word = new int[4];
                word[0] = Mod(w1[0] + w2[0], ALPHABET.Length);
                word[1] = Mod(w1[1] + w2[1], ALPHABET.Length);
                word[2] = Mod(w1[2] + w2[2], ALPHABET.Length);
                word[3] = Mod(w1[3] + w2[3], ALPHABET.Length);
                return word;
            }

            /// <summary>
            /// RotWord operation of keyschedule of AES. See https://en.wikipedia.org/wiki/AES_key_schedule
            /// </summary>
            /// <param name="data"></param>
            int[] RotWord(int[] data)
            {
                var ret = new int[4];
                ret[0] = data[1];
                ret[1] = data[2];
                ret[2] = data[3];
                ret[3] = data[0];
                return ret;
            }

            /// <summary>
            /// Substitutes using the bigram substitution (TextAES S-Box)
            /// </summary>
            /// <param name="data"></param>
            int[] SubWord(int[] data)
            {
                var ret = new int[4];
                for (int i = 0; i < data.Length; i += 2)
                {
                    var sub = SubBigram(new int[] { data[i], data[i + 1] });
                    ret[i] = sub[0];
                    ret[i + 1] = sub[1];
                }
                return ret;
                int[] SubBigram(int[] bigram)
                {
                    var offset = bigram[0] * ALPHABET.Length + bigram[1];
                    var number = SBox[offset];
                    return new int[] { number / ALPHABET.Length, number % ALPHABET.Length };
                }
            }
        }

        #endregion

        #region Encryption and decryption

        public string EncryptECB(string plaintext, string key)
        {
            while(plaintext.Length % 16 > 0)
            {
                plaintext += "X";
            }
            var builder = new StringBuilder();
            for (var i = 0; i < plaintext.Length; i += 16)
            {
                builder.Append(EncryptBlock(plaintext.Substring(i, 16), key));
            }
            return builder.ToString();
        }

        public string DecryptECB(string ciphertext, string key)
        {
            if (ciphertext.Length % 16 != 0)
            {
                throw new ArgumentException("Ciphertext length is no multiple of 16");
            }
            var builder = new StringBuilder();
            for (var i = 0; i < ciphertext.Length; i += 16)
            {
                builder.Append(DecryptBlock(ciphertext.Substring(i, 16), key));
            }
            return builder.ToString();
        }

        public string EncryptBlock(string plaintext, string key)
        {
            if(plaintext.Length != 16)
            {
                throw new ArgumentException("Plaintext length != 16");
            }
            if (key.Length != 16)
            {
                throw new ArgumentException("Key length != 16");
            }
            var numtext = MapTextIntoNumberSpace(plaintext, ALPHABET);
            var numkey = MapTextIntoNumberSpace(key, ALPHABET);
            var ciphertext = Encrypt(numtext, numkey, 10);
            return MapNumbersIntoTextSpace(ciphertext, ALPHABET);
        }

        public string DecryptBlock(string ciphertext, string key)
        {
            if (ciphertext.Length != 16)
            {
                throw new ArgumentException("Ciphertext length != 16");
            }
            if (key.Length != 16)
            {
                throw new ArgumentException("Key length != 16");
            }
            var numtext = MapTextIntoNumberSpace(ciphertext, ALPHABET);
            var numkey = MapTextIntoNumberSpace(key, ALPHABET);
            var plaintext = Decrypt(numtext, numkey, 10);
            return MapNumbersIntoTextSpace(plaintext, ALPHABET);
        }

        /// <summary>
        /// Encrypt using R rounds
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <param name="R"></param>
        /// <returns></returns>
        public int[] Encrypt(int[] text, int[] key, int R)
        {
            //key expansion --> make multiple out of the given key
            var roundkeys = KeyExpansion(key, R + 1);

            //add 0 key
            AddRoundKey(text, GetRoundKey(roundkeys, 0));

            //perform rounds
            for (var r = 1; r < R; r++)
            {
                SubBigrams(text);
                ShiftRows(text);
                MixColumns(text);
                AddRoundKey(text, GetRoundKey(roundkeys, r));
            }

            //final round without mix columns
            SubBigrams(text);
            ShiftRows(text);
            AddRoundKey(text, GetRoundKey(roundkeys, R));

            //return encrypted text
            return text;

            ///Get a round key from the round keys array
            int[] GetRoundKey(int[] data, int offset)
            {
                var word = new int[16];
                word[0] = data[offset * 16 + 0];
                word[1] = data[offset * 16 + 1];
                word[2] = data[offset * 16 + 2];
                word[3] = data[offset * 16 + 3];
                word[4] = data[offset * 16 + 4];
                word[5] = data[offset * 16 + 5];
                word[6] = data[offset * 16 + 6];
                word[7] = data[offset * 16 + 7];
                word[8] = data[offset * 16 + 8];
                word[9] = data[offset * 16 + 9];
                word[10] = data[offset * 16 + 10];
                word[11] = data[offset * 16 + 11];
                word[12] = data[offset * 16 + 12];
                word[13] = data[offset * 16 + 13];
                word[14] = data[offset * 16 + 14];
                word[15] = data[offset * 16 + 15];
                return word;
            }
        }

        /// <summary>
        /// Decrypt using R rounds
        /// </summary>
        /// <param name="text"></param>
        /// <param name="key"></param>
        /// <param name="R"></param>
        /// <returns></returns>
        public int[] Decrypt(int[] text, int[] key, int R)
        {
            //key expansion --> make multiple out of the given key
            var roundkeys = KeyExpansion(key, R + 1);

            //final round without mix columns
            SubtractRoundKey(text, GetRoundKey(roundkeys, R));
            ShiftRowsInverse(text);
            SubBigramsInverse(text);

            //perform rounds
            for (var r = R - 1; r >= 1; r--)
            {
                SubtractRoundKey(text, GetRoundKey(roundkeys, r));
                MixColumnsInverse(text);
                ShiftRowsInverse(text);
                SubBigramsInverse(text);
            }

            //subtract 0 key
            SubtractRoundKey(text, GetRoundKey(roundkeys, 0));

            //return decrypted text
            return text;

            ///Get a round key from the round keys array
            int[] GetRoundKey(int[] data, int offset)
            {
                var word = new int[16];
                word[0] = data[offset * 16 + 0];
                word[1] = data[offset * 16 + 1];
                word[2] = data[offset * 16 + 2];
                word[3] = data[offset * 16 + 3];
                word[4] = data[offset * 16 + 4];
                word[5] = data[offset * 16 + 5];
                word[6] = data[offset * 16 + 6];
                word[7] = data[offset * 16 + 7];
                word[8] = data[offset * 16 + 8];
                word[9] = data[offset * 16 + 9];
                word[10] = data[offset * 16 + 10];
                word[11] = data[offset * 16 + 11];
                word[12] = data[offset * 16 + 12];
                word[13] = data[offset * 16 + 13];
                word[14] = data[offset * 16 + 14];
                word[15] = data[offset * 16 + 15];
                return word;
            }
        }

        #endregion
    }
}
