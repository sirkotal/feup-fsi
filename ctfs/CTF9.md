# CTF 9 - Find-my-TLS

## 1. Reconnaissance

We were given access to a PCAP file containing a large amount of TCS connections - *dump.pcapng*. The goal of this CTF was to reconstruct the flag by analyzing various bits of information from one specific TCS connection, using Wireshark.

The flag has the following structure: *flag{<frame_start>-<frame_end>-<selected_cipher_suite>-<total_encrypted_appdata_exchanged>-<size_of_encrypted_message>}*, where:

- <frame_start> and <frame_end> are the first and last (respectively) frame numbers corresponding to the TLS handshake procedure.
- <selected_cipher_suite> is the chosen cipher suite for the TLS connection (the name of the suite, not its code).
- <total_encrypted_appdata_exchanged> is the total sum of the size of encrypted data exchanged on this channel until its termination.
- <size_of_encrypted_message> is the size of the encrypted message in the handshake that completes the handshake procedure.

## 2. Searching for the Flag

We started by narrowing down the amount of messages we had to analyze by adding the ```tls && tls.handshake.type == 1``` filter to Wireshark's filter bar, which allowed us to see only the *Client Hello* messages within the TLS traffic.

After searching through the frames displayed, we finally managed to find the one with the specified random number (```52362c11ff0ea3a000e1b48dc2d99e04c6d06ea1a061d5b8ddbf87b001745a27```) - **frame 814**.

![frame-814](images/find-my-tls-ctf/frame_814.png)

Having found the first frame corresponding to the target TLS handshake procedure, we then had to find its last frame, so we decided to remove the ```tls.handshake.type == 1``` option from the filter bar so that we could analyze every TLS packet in the log.
By inspecting the next frames, we were able to find the one that corresponded to the last frame of the handshake procedure - **frame 819**.

![frame-819](images/find-my-tls-ctf/frame_819.png)

Our next task was to find what was the ciphersuite chosen for the TLS connection; to achieve this, we decided to inspect frame 816 (*Server Hello, Certificate, Server Hello Done*). By investigating the *Handshake Protocol* section, we were able to discover the ciphersuite used for this particular connection - **TLS_RSA_WITH_AES_128_CBC_SHA256**

![ciphersuite](images/find-my-tls-ctf/ciphersuite.png)

The next step was to find the total size of the encrypted app data that was exchanged. For this reason, we decided to inspect the *Application Data* frames (frames 820 and 821) to check what was the size of the exchanged data.

The first frame's data had a length of **80**.

![app-data-one](images/find-my-tls-ctf/app_data_one.png)

The second frame's data had a length of **1184**.

![app-data-two](images/find-my-tls-ctf/app_data_two.png)

This made for a total encypted app data size of **1264**.

Finally, all that was left was to find out the size of the encrypted message that concludes the handshake procedure; for this reason, we went back to frame 819 and extracted the length of the message - **80**.

![encrypted-message-size](images/find-my-tls-ctf/final_message_size.png)

## 3. Constructing the Flag

Having gathered this data, we were able to construct the correct flag: **flag{814-819-TLS_RSA_WITH_AES_128_CBC_SHA256-1264-80}**