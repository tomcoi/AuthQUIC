AuthQUIC Demo README
====================

Overview
--------
This demo showcases the AuthQUIC protocol in which the client obtains a session token from the server via a simple challenge–response exchange over QUIC/TLS.

Files
-----
 server.py  
 client.py  
 cert.pem (server certificate)  
 key.pem (server private key)  

Prerequisites
-------------
 Python 3.7 or later  
 aioquic library   
 The files `cert.pem` and `key.pem` must be in the working directory  


Usage
-----

1. Start the server

   python3 server.py --host 0.0.0.0 --port 12345 --cert cert.pem --key key.pem

   ```
   `--host 0.0.0.0`: Listen on all network interfaces  
   `--port 12345`: Port number, can be changed as needed  
   `--cert cert.pem`: Path to the server’s TLS certificate  
   `--key key.pem`: Path to the server’s TLS private key  

2. Run the client  
  
   python3 client.py --host 127.0.0.1 --port 12345 --username user1 --password abc123 --client-id clientA --insecure

   ```
   `--host 127.0.0.1`: Server IP or hostname 
   `--port 12345`: Server port 
   `--username user1`: Username for authentication  
   `--password abc123`: Password for authentication  
   `--client-id clientA`: Unique client identifier  
   `--insecure`: Skip certificate verification (for self-signed cert)  

Notes
-----
  • To use proper TLS validation, delete `--insecure` and ensure the client trusts `cert.pem`.  
 

