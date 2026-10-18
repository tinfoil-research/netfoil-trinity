## Bootstrap keys
```
./bootstrap-keys.sh
```

## Set CA secrets
```
cat ca.key | systemd-creds encrypt --name=netfoil-hi-ca - /etc/credstore.encrypted/netfoil-hi-ca
```

## Configure CA

### Debian/Ubuntu
Copy to `/usr/local/share/ca-certificates/`
Then
```
update-ca-certificates
```

### Fedora
Copy to `/etc/pki/ca-trust/source/anchors/`
Then
```
update-ca-certificates
```
