.PHONY: all certs keys
all:

root_ca_key_filename := root-key.pem
root_ca_cert_filename := root-ca.pem
server_key_filename := server-key.pem
client_key_filename := client-key.pem client2-key.pem
server_cert_filename := server-cert.pem
client_cert_filename := client-cert.pem client2-cert.pem

all: keys certs
keys: $(root_ca_key_filename) $(server_key_filename) $(client_key_filename)
certs: $(root_ca_cert_filename) $(server_cert_filename) $(client_cert_filename)

.PHONY: clean
clean:
	$(RM) *.srl
	$(RM) $(root_ca_cert_filename) $(root_ca_key_filename)
	$(RM) $(server_key_filename)
	$(RM) $(client_key_filename)
	$(RM) $(server_cert_filename)
	$(RM) $(client_cert_filename)

%-key.pem:
	openssl genpkey -algorithm RSA -out $@ -outform PEM -pkeyopt rsa_keygen_bits:2048
#NOTE: 此处也可以更换公钥算法, 改为生成椭圆曲线（代替RSA）
#	openssl ecparam -name secp384r1 -genkey -noout -out $@

%-cert.pem: %-csr.pem root-ca.pem root-key.pem
	openssl x509 -req -in $< -out $@ -CA root-ca.pem -CAkey root-key.pem -days 36500

%-csr.pem: %-key.pem
	openssl req -new -key $< -out $@ -subj /CN=test_$*/

root-ca.pem: root-key.pem
	openssl req -new -x509 -nodes -days 36501 -key $< -out $@ -subj /CN=test_rootCA/
	test -f root-ca.srl || echo 00 > root-ca.srl
