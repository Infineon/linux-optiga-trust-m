# Simple Server and Client Example using external public key and certificate files

The following example show how to use the key slot 0xE0F1 to generate new key, save the public key and certificate into external file and use the it for TLS connection in C code example. 

* Go to **\linux-optiga-trust-m\scripts\SimpleServeClientTest\SimpleServeClient_with_pubkeyfile**  and  copy **simpleTest_Client.c** and  **simpleTest_Server.c** into **\linux-optiga-trust-m\ex_cli_applications**

  The simpleTest_Server.c has been modified as follow to use external public key file:

  ```
  #define SERVER_CERT "server1.crt"
  #define SERVER_KEY "0xe0f1:server1.pub"
  #define CA_CERT "OPTIGA_Trust_M_Infineon_Test_CA.pem"
  
  
  // Macro for Engine
  #define ENGINE_NAME "trustm_engine"
  ```

  The simpleTest_Client.c  has been modified as follow:

  ```
  // Macro for Keys/Certificates
  #define CA_CERT "OPTIGA_Trust_M_Infineon_Test_CA.pem"
  ```

  

* Run **sudo make uninstall**  under  **\linux-optiga-trust-m** to uninstall the previous installed componenets

* Run **make -j5** under  **\linux-optiga-trust-m** to compile 

* Run **sudo make install**  under  **\linux-optiga-trust-m** to install the tools

* Configure the path parameters in "**config.sh**" as follow according to the project directory path for "bin" and "certificates" folders :

  ```
  EXEPATH="/home/pi/linux-optiga-trust-m/bin"
  CERT_PATH="/home/pi/linux-optiga-trust-m/scripts/certificates"
  ```

  

* Run **step1a_generate_keys_wo_pkey_store.sh** to generate keypair, external public key and server certificate as follow:

  ```
  pi@raspberrypi:~/linux-optiga-trust-m/scripts/SimpleServeClientTest/SimpleServeClient_with_pubkeyfile $ ./step1a_generate_keys_wo_pkey_store.sh 
  Server1:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request
  engine "trustm_engine" set.
  Certificate Request:
      Data:
          Version: 1 (0x0)
          Subject: CN = server1
          Subject Public Key Info:
              Public Key Algorithm: id-ecPublicKey
                  Public-Key: (256 bit)
                  pub:
                      04:ea:25:15:07:eb:14:81:7a:64:82:0b:50:73:d0:
                      30:7f:57:92:c0:3f:95:73:01:77:3a:4e:99:1d:6d:
                      bf:4d:8b:3a:8c:89:41:b0:1a:d9:9b:65:8c:01:59:
                      b1:99:d7:bf:cc:85:4d:82:62:85:97:01:58:1f:fe:
                      9b:dd:43:c7:e6
                  ASN1 OID: prime256v1
                  NIST CURVE: P-256
          Attributes:
              a0:00
      Signature Algorithm: ecdsa-with-SHA256
           30:45:02:21:00:8c:80:7a:01:af:2b:9d:65:62:4b:f0:e7:9b:
           58:3b:cb:80:d9:7e:65:f0:cb:67:ac:a9:75:dc:49:8f:3c:91:
           0a:02:20:57:9c:60:e6:8c:4e:7e:24:02:b4:74:b2:c1:c6:8c:
           65:ac:49:59:63:6d:7c:df:d7:14:c0:c3:be:98:76:a0:41
  -----BEGIN CERTIFICATE REQUEST-----
  MIHMMHQCAQAwEjEQMA4GA1UEAwwHc2VydmVyMTBZMBMGByqGSM49AgEGCCqGSM49
  AwEHA0IABOolFQfrFIF6ZIILUHPQMH9XksA/lXMBdzpOmR1tv02LOoyJQbAa2Ztl
  jAFZsZnXv8yFTYJihZcBWB/+m91Dx+agADAKBggqhkjOPQQDAgNIADBFAiEAjIB6
  Aa8rnWViS/Dnm1g7y4DZfmXwy2esqXXcSY88kQoCIFecYOaMTn4kArR0ssHGjGWs
  SVljbXzf1xTAw76YdqBB
  -----END CERTIFICATE REQUEST-----
  
  Bypass Shielded Communication. 
  ========================================================
  App DataStrucObj type 3     [0xF1D1] 
  [Size 0001] : 	00 
  ========================================================
  Server1:-----> extract public key from CSR
  Server1:-----> Generate server cetificate by using CA
  Signature ok
  subject=CN = server1
  Getting CA Private Key
  Server1:-----> Verify server cetificate by using CA
  server1.crt: OK
  Chain:
  depth=0: CN = server1 (untrusted)
  depth=1: C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM), CN = Infineon OPTIGA(TM) Trust M Test CA 000
  
  ```

  

* Execute the "***update latest exe.sh***":

  ```
  pi@raspberrypi:~/linux-optiga-trust-m/scripts/SimpleServeClientTest/SimpleServeClient_with_pubkeyfile $ ./update_latest_exe.sh 
  Copy simpleTest executable into current directory
  pi@raspberrypi:~/linux-optiga-trust-m/scripts/SimpleServeClientTest/SimpleServeClient_with_pubkeyfile $ ls -l
  total 84
  -rwxr-xr-x 1 pi pi   107 Sep  9 14:15 config.sh
  -rw-r--r-- 1 pi pi   329 Sep  8 16:35 openssl.cnf
  -rw-r--r-- 1 pi pi   898 Sep  8 16:35 OPTIGA_Trust_M_Infineon_Test_CA.pem
  -rw-r--r-- 1 pi pi  1022 Sep  8 16:35 README.md
  -rw-r--r-- 1 pi pi   704 Sep  9 14:22 server1.crt
  -rw-r--r-- 1 pi pi   351 Sep  9 14:22 server1.csr
  -rw-r--r-- 1 pi pi   529 Sep  9 14:22 server1.pub
  -rwxr-xr-x 1 pi pi 13688 Sep  9 14:28 simpleTest_Client
  -rw-r--r-- 1 pi pi  5282 Sep  8 16:35 simpleTest_Client.c
  -rwxr-xr-x 1 pi pi 14596 Sep  9 14:28 simpleTest_Server
  -rw-r--r-- 1 pi pi  8054 Sep  8 16:35 simpleTest_Server.c
  -rwxr-xr-x 1 pi pi   939 Sep  9 14:22 step1a_generate_keys_wo_pkey_store.sh
  -rwxr-xr-x 1 pi pi   117 Sep  9 14:21 update_latest_exe.sh
  
  ```

  

* Run **./simpleTest_Server** and  **./simpleTest_Client** under current folder

    Example of simpleTest_Server running without client connection

  ```console
  pi@raspberrypi:~/linux-optiga-trust-m/scripts/SimpleServeClientTest/SimpleServeClient_with_pubkeyfile $ ./simpleTest_Server 
  89 main: *****************************************
  141 serverListen: Listening to incoming connection
  ```

  #### Running the Client

  Open another new terminal in the system and ensure *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* is in the current folder. Run simpleTest_Client

  Example of simpleTest_Client running with connection to server

  ```
  pi@raspberrypi:~/linux-optiga-trust-m/scripts/SimpleServeClientTest/SimpleServeClient_with_pubkeyfile $ ./simpleTest_Client 
  88 main: *****************************************
  113 doClientConnect: s_ipaddr : 127.0.0.1
  150 doClientConnect: Connecting to server ....
  168 doClientConnect: Connected to 127.0.0.1, port :0x8813
  190 doClientConnect: Performing Handshaking .....
  199 doClientConnect: Connection using : TLS_AES_256_GCM_SHA384
  200 doClientConnect:                  : TLSv1.3
  From Server [11072] : 001
  From Server [11072] : 002
  From Server [11072] : 003
  From Server [11072] : 004
  From Server [11072] : 005
  ```

  Server terminal output

  ```console
  pi@raspberrypi:~/linux-optiga-trust-m/scripts/SimpleServeClientTest/SimpleServeClient_with_pubkeyfile $ ./simpleTest_Server 
  89 main: *****************************************
  144 serverListen: Listening to incoming connection
  157 serverListen: Connection from 127.0.0.1, port :0xe48f
  144 serverListen: Listening to incoming connection
  236 doServerConnected: Engine ID : trustm_engine
  242 doServerConnected: Init TrustM Engine. Ok
  248 doServerConnected: Set Default Engine Ok.
  261 doServerConnected: Load Certificate ok
  269 doServerConnected: Private Key Match the Server Certificate.
  278 doServerConnected: Load CA cert ok
  301 doServerConnected: Performing Handshking ......... 
  306 doServerConnected: Connection using : TLS_AES_256_GCM_SHA384
  307 doServerConnected:                  : TLSv1.3
  308 doServerConnected: ++++++++++++++++++++++++++++++++++++++++++++++
  328 doServerConnected: [12081] Received : 1
  328 doServerConnected: [12081] Received : 2
  328 doServerConnected: [12081] Received : 3
  328 doServerConnected: [12081] Received : 4
  328 doServerConnected: [12081] Received : 5
  ```

  

  
