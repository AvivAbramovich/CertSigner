# CertSigner

Easly create and sign new certificates using given CA certificate.

Example:
```
from signer import PyOpenSSLCertSigner as CertSigner

signer = CertSigner.create_from_paths('/path/to/key.pem', '/path/to/cert.pem')

domain = 'your.domain.com'
days = 3650
key_length = 3560
subj = '/O=my-org'  # same format as openssl req -subj xxx

crt, key = signer.sign_domain(domain, days, subj, key_length)

print('crt: \n{}'.format(crt.decode('utf-8')))
print('key: \n{}'.format(key.decode('utf-8')))
```

## Flask app
Use Flask to publish the signer service to your costumers

Example:
```
python app.py --ca_crt /path/to/cert.pem --ca_key /path/to/key.pem
```

Then request the app.
Exaple use curl
```
curl localhost?q=your.domain.com
```
That returns a zip file with cert.pem and key.pem

Other query arguments:
```
as-text -       returns html with cert and key as text rather than zip file
key_len -       The private key length
subj -          request subject string
days -          days until cert expired
```

## Docker container
Easly publish the flask app
```
docker run -v /path/to/cert.pem:/certs/cert.pem -v /path/to/key.pem:/certs/key.pem certifier
```
mount the CA cert and key into `CA_CRT` and `CA_KEY` respectively.

Options:

`CA_CRT` -      path to CA cert file \
`CA_KEY` -      path to CA key file \
`DAYS`   -      default value for days \
`SUBJ`   -      default value for subj \
`KEY_LEN`-      default value for key length

