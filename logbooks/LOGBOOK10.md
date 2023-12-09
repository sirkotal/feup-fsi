# LOGBOOK 10

The Secret-Key Encryption Lab main goal is to make students familiar with secret-key encryption concepts. Secret-key encryption, also known as symmetric-key cryptography, is a cryptographic method where the same secret key is used for both encryption and decryption of data. This key is shared between the sender and receiver of the encrypted data, and the key must be kept secret to ensure that only they can access the information.


## Task 1: Frequency Analysis

For Task 1, we had to find out the original text of a ciphertext that had been encrypted using a monoalphabetic cipher with frequency analysis. Monoalphabetic substitution cipher is not secure, precisely because it can be subjected to frequency analysis. **Frequency analysis is a technique that exploits the fact that there is a statistical pattern in the distribution of letters that is more or less the same for almost all text samples of a certain language**. 
The lab guide indicated that the original text is in English. Some simplifications were made when encrypting the file in order to facilitate frequency analysis, such as converting all upper cases to lower cases and then removing all the punctuation and numbers. Spaces between words were also kept to facilitate checking word boundaries. In real encryption using monoalphabetic cipher, spaces would have been removed.

To find out the original text, we needed to discover the encryption key used, in order to then decrypt the ciphertext. The lab guide provided a Python program that reads the `ciphertext.txt` file, and produces the statistics of single-letter frequencies, bigram frequencies and trigram frequencies. We ran the program and the results were the following:

![freq.py](./images/logbook10/lab10_freq.png){width=50%}

*Figure 1. Output of freq.py program*


Since we knew the original text was in English, we checked online sources to know what the [letter frequencies are in the English language](https://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html#bigrams) and match it with the results obtained from the previously mentioned Python program.

We started by replacing the top 4 most frequent single-letters present in the ciphertext {n, y, v, x}  for the top 4 most frequent single-letters present in the English language {e, t, a, o} respectively. We knew that most likely there wouldn't be an exact match between the single-letters frequency of the ciphertext and the single-letters frequency present in the English language, so we also analyzed bigram and trigram frequencies of the ciphertext against the ones most frequent in English language. This allowed us to infer the meaning of more single-letters. By replacing the top 4 most frequent single-letters followed by some bigrams and trigrams, we started to see some words in the cypher text to take shape and this allowed us to infer more letters. Through this repetitive process, we found the key and the original text. **The key was {cfmypvbrlqxwiejdsgkhnazotu}**. We used the `tr` command to replace the letters in ciphertext for the encryption key.

![cypher text decrypted](./images/logbook10/lab10_task1.png){width=50%}

*Figure 2. Use of tr command and cypher text decrypted*



## Task 2: Encryption using Different Ciphers and Modes


For Task 2, we had to encrypt a text using different encryption algorithms and modes.  We used the plaintext decrypted in Task 1 to encrypt it again with the different algorithms. For that effect, we used the `enc` command from the *openssl* library. This command allows us to encrypt or decrypt data.

```bash
$ openssl enc -ciphertype -e -in plain.txt -out cipher.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708
```

We simply replaced `-ciphertype` with the corresponding cipher type.

![task2_all_cipher_types](./images/logbook10/task2_all_cipher_types.png){width=50%}

*Figure 3. Encryption with different cipher types*


- **Cipher Block Chaining (CBC)**

Cipher Block Chaining (CBC) is a mode of operation for a block cipher, which is a cryptographic algorithm that transforms a fixed-sized block of data into another fixed-sized block of data.

Result for ciphertype `aes-128-cbc`:


![Cipher Block Chaining](./images/logbook10/task2_cypher_cbc.png){width=35%}

*Figure 4. CBC Encryption Result*


Result for ciphertype `-bf-cbc`:

![task2_cypher3](./images/logbook10/task2_cypher3.png){width=35%}

*Figure 5. Cipher Block Chaining Encryption Result*


- **Cipher Feedback (CFB)**

Cipher Feedback (CFB) is a mode of operation for a block cipher that utilizes the previous ciphertext block as feedback to encrypt the current plaintext block. This process results in a stream of cipher-like output, providing a more efficient and flexible encryption method compared to other block cipher modes like Electronic Codebook (ECB) and Cipher Block Chaining (CBC).

![task2_cypher_text_cfb](./images/logbook10/task2_cypher_text_cfb.png){width=35%}

*Figure 6. CFB Encryption Result*



## Task 3: Encryption Mode – ECB vs. CBC

For Task 3, we were asked to encrypt a picture file named `pic original.bmp` using the ECB (Electronic Code Book) and CBC (Cipher Block Chaining) modes.
We started by encrypting the file in the same way we did in the previous task using both techniques (ECB and CBC).

![task3_pic](./images/logbook10/task3_pic.png){width=50%}

*Figure 7. Picture encryption with different modes*

The result was the following:

![task3_header_error](./images/logbook10/task3_header.png){width=35%}

*Figure 8. Picture rendering issue*

The resulting encrypted file could not be loaded because the header was also encrypted and, therefore, it was not possible to render the picture file. For the *.bmp* file, the first 54 bytes contain the header information about the picture; to solve the previous issue, we have to set it correctly. We replaced the header of the encrypted picture with the one from the original picture by extracting the header from the original file, the data from encrypted picture and combine them together into a new file.

- **For the CBC mode:**

![task3_head_tail_cbc](./images/logbook10/task3_head_tail_cbc.png){width=50%}

*Figure 9. Header extraction for CBC mode picture encryption*

- **For the ECB mode:**

![task3_pic_ecb](./images/logbook10/task3_pic_ecb.png){width=50%}

*Figure 10. Header extraction for ECB mode picture encryption*


After correcting the header bytes, we were able to render the encrypted picture files. The results were the following:


- **For the CBC mode:**

![pic_cbc_task3](./images/logbook10/pic_cbc_task3.png){width=35%}

*Figure 11. CBC encrypted picture file*

- **For the ECB mode:**

![task3_ecb](./images/logbook10/task3_ecb.png){width=35%}

*Figure 12. ECB encrypted picture file*


- As shown in the results, the encrypted image produced using ECB mode is practically the same as the original one and, therefore, very inefficient regarding its purpose, since anyone with some knowledge of the original picture could easily decrypt it. This is because, in ECB mode, each block of plaintext is encrypted independently and so, if there are identical blocks in the original picture, they will encrypt to identical ciphertext blocks. With ECB mode, patterns and repetitions in the original data are preserved in the encrypted output.

- With the CBC mode however, the resulting encrypted file has no relation whatsoever to the original picture file, making it much harder to decrypt and hence much safer. This can be explained by the fact that in CBC mode each block of plaintext is XORed with the previous ciphertext block before encryption. This introduces a dependency between blocks and so, even if the original picture has identical blocks, the XOR operation ensures that the input to the encryption algorithm is different for each block. This dependency breaks up patterns in the original data, and even small changes in the input result in a completely different ciphertext block.

