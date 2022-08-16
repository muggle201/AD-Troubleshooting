https://medium.com/@robert.broeckelmann/kerberos-wireshark-captures-a-windows-login-example-151fabf3375a

# KRB_KDC_REQ Definition
根据application tag来确认是KRB_AS_REQ或KRB_TGS_REQ，由Client发送至KDC来请求下一项服务的credentials。<br>
AS-REQ ::= [APPLICATION 10] KDC-REQ<br>
TGS-REQ ::= [APPLICATION 12] KDC-REQ<br>