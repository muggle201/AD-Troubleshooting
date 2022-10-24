Schannel是SSP，使用SSL或TLS。TLS/SSL基于PKI。

## Prictical application

- Transactions with an e-commerce website
- Remote access
- SQL access
- E-mail



TLS/SSL protocols are located between the application protocol layer and the TCP/IP layer.



The Secure Channel (Schannel) security package, whose authentication service identifier is RPC_C_AUTHN_GSS_SCHANNEL.

 

TLS is the only security option available when **servers need to prove their identity to anonymous clients**. 

Additionally, TLS provides the option of having clients prove their identity to servers.

 

For example, you can use TLS/SSL for:

\- SSL-secured transactions with an e-commerce website

\- Authenticated client access to an SSL-secured website

\- Remote access

\- SQL access

\- E-mail

 

 

Kerberos need KDC holds everyone's account database, secure channel relies upon a PKI.

 

\- Secure communication

Sender encrypt the message with the public key of receiver.

 

\- Integrity

Sender attach a digital signature before sending:

\- Calculating the hash of the data. (Receiver will use the same algorithm to calculate it either.)

\- Encrypt it with sender's private key