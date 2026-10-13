openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key

openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt
openssl x509 -in ca.crt -text -noout
