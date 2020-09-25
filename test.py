from signer import PyOpenSSLCertSigner as CertSigner
from argparse import ArgumentParser
from os.path import join
import logging

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

if __name__ == '__main__':
    args_parser = ArgumentParser()
    args_parser.add_argument('domain', help='domain to sign')
    args_parser.add_argument('--ca_crt', help='path to CA cert', default=join('certs','cert.pem'))
    args_parser.add_argument('--ca_key', help='path to CA private key', default=join('certs','key.pem'))
    args_parser.add_argument('--key_len', help='the private key length', type=int, default=4096)
    args_parser.add_argument('--subj', help='default subject', default='/O=org')
    args_parser.add_argument('--days', help='days for certificate', type=int, default=3650)
    args = args_parser.parse_args()

    signer = CertSigner.create_from_paths(args.ca_key, args.ca_crt)

    logger.info('signing "%s"', args.domain)
    crt, key = signer.sign_domain(args.domain, args.days, key_length=args.key_len, subject_str=args.subj)
    print('cert: \n{}\n\nkey:\n{}'.format(crt, key))

