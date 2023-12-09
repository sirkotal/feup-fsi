# LOGBOOK 11

This lab's objective was to learn more about Public Key Infrastructures.
Public key cryptography is the foundation of today’s secure communication; however, it is vulnerable to man-in-the-middle attacks when one party transmits its public key to another. The Public Key Infrastructure (PKI) presents a practical solution to verify the ownership of a public key.

## Environment Setup

To set up this lab, it was first necessary to run the command ```docker-compose up``` inside the ```Labsetup``` folder that contains the *docker-compose.yml* file.
After this, we added the following entry to the ```/etc/hosts``` file on our VM.

```bash 
10.9.0.80       www.l04g05fsi2324.com
```

## Task 1: Becoming a Certificate Authority (CA)

Initially, it was necessary to copy the file that can be found at ```/usr/lib/ssl/openssl.cnf``` to the current directory, followed by the creation a new directory, *demoCa*, with 3 additional directories inside it: *certs*, *crl* and *newcerts*.
It was also necessary to create an empty file on the *demoCa* directory - the *index.txt* - and a serial file with a single number in string format.

The next step was running the following command to generate the CA certificate:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -keyout ca.key -out ca.crt
```

The password we used was ```fsi2345``` and the following data was also requested:

![certificate-data](images/logbook-11/certificate-data.png)

After this, two files were generated: ```ca.key```, which contains the CA's private key, and ```ca.crt```, with the public key certificate.

The certificate's content can be obtained using ```openssl x509 -in ca.crt -text -noout``` and the key's content using ```openssl rsa -in ca.key -text -noout```.

After running these commands, we were then able to answer some questions:

# What part of the certificate indicates this is a CA’s certificate?

On the section Certificate > Data > X509v3 extensions > X509v3 Basic Constraints, after using ```openssl x509 -in ca.crt -text -noout```, an atribute ```CA``` identifies whether that certificate belongs to a CA.

![ca-variable](images/logbook-11/ca-variable.png)

# What part of the certificate indicates this is a self-signed certificate?

Using the same command as in the previous question, we find that the Subject Key Identifier and the Authority Key Identifier are equal, meaning that the certificate is self-signed.

![ca-variable](images/logbook-11/ca-variable.png)

# In the RSA algorithm, we have a public exponent e, a private exponent d, a modulus n, and two secret numbers p and q, such that n = pq. Please identify the values for these elements in your certificate and key files

By running ```openssl rsa -in ca.key -text -noout``` we can check that:
    - the ```modulus``` camp gives us the n (modulus);
    - ```prime1``` and ```prime2``` are the two secret numbers (p and q);
    - the ```publicExponent``` has the, as the name tells, the public exponent (e);
    - the ```privateExponent``` show us the private exponent (d);
    

## Task 2: Generating a Certificate Request for Your Web Server

The objective of this task was to generate a Certificate Request to our Web Server. To achieve this, all we needed to do was to run the following command:

```bash
openssl req -newkey rsa:2048 -sha256 -keyout server.key -out server.csr -subj "/CN=www.l04g05fsi2324.com/O=L04G05 Inc./C=PT" -passout pass:dees -addext "subjectAltName = DNS:www.l04g05fsi2324.com, DNS:www.l04g05fsi2324A.com, DNS:www.l04g05fsi2324b.com" 
```

This generated a CSR for the domain ```www.l04g05fsi2324.com``` and the alternative names attached (```www.l04g05fsi2324A.com``` and ```www.l04g05fsi2324B.com```).

![csr](images/logbook-11/csr.png)

## Task 3: Generating a Certificate for your server

Firstly, we were told to uncomment the ```copy_extensions = copy``` because, for security reasons, the default setting in *openssl.cnf* does not allow the ```openssl ca``` command to copy the extension field from the request to the final certificate.

```bash
openssl ca -config openssl.cnf -policy policy_anything -md sha256 -days 3650 -in server.csr -out server.crt -batch -cert ca.crt -keyfile ca.key
```

By running the previous command, we managed to conclude this task sucessfully.

![server-key](images/logbook-11/server-key.png)

We were able to assume that by running  ```openssl x509 -in server.crt -text -noout```

![check-server-key](images/logbook-11/check-server-key.png)

## Task 4: Deploying Certificate in an Apache-Based HTTPS Website

The first thing to do was to change the ```bank32_apache_ssl.conf```, as shown below.

```bash
<VirtualHost *:443>
    DocumentRoot /var/www/bank32
    ServerName www.l04g05fsi2324.com
    ServerAlias www.l04g05fsi2324A.com
    ServerAlias www.l04g05fsi2324B.com
    DirectoryIndex index.html
    SSLEngine On
    SSLCertificateFile /volumes/server.crt
    SSLCertificateKeyFile /volumes/server.key
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/bank32
    ServerName www.l04g05fsi2324.com
    DirectoryIndex index_red.html
</VirtualHost>

# Set the following gloal entry to suppress an annoying warning message
ServerName localhost
```

The previous step was then followed by starting the Apache server with ```service apache2 start```, although, at first, we couldn't access ```https://www.l04g05fsi2324.com``` because the connection was not safe. 

![website_unsafe](images/logbook-11/website-unsafe.png)

To fix this, it was necessary to import the CA certificate (```ca.crt```). This was done by doing ```about:preferences#privacy -> Certificates -> View Certificates -> Authorities -> Import```.

![import_ca](images/logbook-11/import-ca.png)

The website connection was then safe!

![website_safe](images/logbook-11/website-safe.png)

## Task 5: Launching a Man-In-The-Middle Attack

On this task, we changed the ```bank32_apache_ssl.conf``` again, but this time we only altered the server name to ```www.example.com```. We also needed to add this to ```etc/hosts```.

When we tried to access ```https://example.com```, we were able to check that the connection was not safe, as in the beginning of Task 4; this was because it was not an entry registered in CA.

![example_unsafe](images/logbook-11/example-unsafe.png)

## Task 6: Launching a Man-In-The-Middle Attack with a Compromised CA

As told in the lab, we worked as if the private key of the CA had been compromised, meaning that we could generate certificates for more websites. The reason for this was that the CA was trusted by this machine.

Going back to Task 2, we ran the following commands - the same as before but this time for ```www.example.com```.

```bash
openssl req -newkey rsa:2048 -sha256 -keyout example.key -out example.csr -subj "/CN=www.example.com/O=example Inc./C=PT" -passout pass:dees -addext "subjectAltName =  DNS:www.example.com"

openssl ca -config openssl.cnf -policy policy_anything -md sha256 -days 3650 -in example.csr -out example.crt -batch -cert ca.crt -keyfile ca.key
```

To finalize the task, we made some changes to ```bank32_apache_ssl.conf``` in order to use the new certicate.

```bash
<VirtualHost *:443>
    DocumentRoot /var/www/bank32
    ServerName www.example.com
    DirectoryIndex index.html
    SSLEngine On
    SSLCertificateFile /volumes/example.crt
    SSLCertificateKeyFile /volumes/example.key
</VirtualHost>

<VirtualHost *:80>
    DocumentRoot /var/www/bank32
    ServerName www.example.com
    DirectoryIndex index_red.html
</VirtualHost>

# Set the following global entry to suppress an annoying warning message
ServerName localhost
```

Accessing the website, we were able to verify that it was then safe!

![example_safe](images/logbook-11/example-safe.png)
