# AES-and-Text-Based-AES
Implementations of the real AES cipher and my Text-Based AES cipher in C#

These implementations were created for my YouTube channel "Cryptography for everybody" for the creation of my AES videos to refresh my understanding of the details of AES.
- Video about AES: https://www.youtube.com/watch?v=h6wvqm0aXco
- Video about AES key schedule: https://www.youtube.com/watch?v=rmqWaktEpcw

My YouTube channel: https://www.youtube.com/c/CrypTool2/
My blog: https://www.kopaldev.de
Another repository with source code in C# for a console application which allows file encryption using AES and a password: https://github.com/n1k0m0/FileCrypt

## AES
Implementation of the Advanced Encryption Standard (AES). For details on AES/Rijndael, see 
- Daemen, Joan; Rijmen, Vincent (2002). The Design of Rijndael: AES – The Advanced Encryption Standard. Springer. ISBN 978-3-540-42580-9.

The purpose of this implementation is to make it as easily as possible to understand AES. Thus, we tried to create only
easy to read implementations of the primitives. Also, there is no further speed optimization with lookup tables for the
Galois arithmetic being the exception. Finally, there are no special security measures like protecting keys in
memory or measures against side channel attacks. Thus, this implementation should be only used for educational purposes
and NOT for any security purposes!

## Text-Based AES
"Crazy AES-like cipher" that only works on text data (Latin Alphabet A-Z)
The structure of the cipher is based on the same structure of AES with some changes:
- The S-Box is a bigram substitution (randomly created fixed table) instead of a byte-based substitution
- XOR-ing the keys is replaced by a shift cipher (just adds and subtracts the roundkeys)
- ShiftRows is exactly the same as with original AES
- MixColumns is replaced by a Hill cipher (still matrix multiplication :-)), we use the "original" matrix for encryption
- KeyExpansion is exchanged completely (uses ShiftRows, MixColumns, and round constants from AAAA-ZAAA to expand the key)
- We also perform 10 rounds like AES-128
- We define the mapping from letters to numbers as: A=0, B=1, C=2, ..., Z=25
