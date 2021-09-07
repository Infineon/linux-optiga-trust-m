# Steps to test simpleTestSeverClient using pubkey file

To use the key slot 0xE0F1 to generate key and save the public key into external file 

* Go to **\linux-optiga-trust-m\scripts\SimpleServeClientTest\SimpleServeClient_with_pubkeyfile**  and  copy **simpleTest_Client.c** and  **simpleTest_Server.c** into **\linux-optiga-trust-m\ex_cli_applications**

* Run **sudo make uninstall**  under  **\linux-optiga-trust-m** to uninstall the previous tools

* Run **make -j5** under  **\linux-optiga-trust-m** to compile 

* Run **sudo make install**  under  **\linux-optiga-trust-m** to install the tools

* Go to folder  **\linux-optiga-trust-m\scripts\SimpleServeClientTest\SimpleServeClient_with_pubkeyfile**   and run **update latest exe.sh** to copy simpleTest_Server.exe and simpleTest_Server.exe into current folder

* Run **step1a_generate_keys_wo_pkey_store.sh** to generate keypair

* Run **./simpleTest_Server** under current folder

* Run **./simpleTest_Client** under current folder

    
