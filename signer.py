import subprocess
import re
from OpenSSL import crypto
from abc import ABCMeta, abstractmethod


class ICertSigner:
    __metaclass__ = ABCMeta

    @abstractmethod
    def sign_domain(self, domain, days, subject_str=None, key_length=4096):
        pass

    @staticmethod
    def _subj_parse(subj, s):
        keys = ['C', 'ST', 'L', 'O', 'OU', 'CN']
        pattern = r'/({})=([^/]+)'.format('|'.join(keys))
        for key,val in re.findall(pattern, s):
            setattr(subj, key, val)


class SubprocessScriptCertSigner(ICertSigner):
    def __init__(self, ca_key_path, ca_crt_path, script_path='script.sh'):
        self._ca_key_path = ca_key_path
        self._ca_crt_path = ca_crt_path
        self._script_path = script_path

    def sign_domain(self, domain, days, subject_str=None, key_length=4096):
        res = subprocess.Popen(["bash", self._script_path, domain],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = res.communicate()
        if res.returncode != 0:
            raise Exception('failed to sign "{}": {}'.format(domain, stderr))

        pattern = '-+BEGIN {0}-+(\n|.)*-+END {0}-+'
        # split stdout to crt and key
        crt_matches = re.search(pattern.format('CERTIFICATE'), stdout)
        if not crt_matches:
            raise Exception('no certificate found in results: {}'.format(stdout))
        key_matches = re.search(pattern.format('RSA PRIVATE KEY'), stdout)
        if not key_matches:
            raise Exception('no private key found in results: {}'.format(stdout))

        return crt_matches.group(), key_matches.group()


class PyOpenSSLCertSigner(ICertSigner):
    def __init__(self, ca_key, ca_crt):
        self._ca_key = ca_key
        self._ca_crt = ca_crt

    @staticmethod
    def create_from_paths(ca_key_path, ca_crt_path):
        with open(ca_key_path) as f_key, open(ca_crt_path) as f_crt:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f_key.read())
            crt = crypto.load_certificate(crypto.FILETYPE_PEM, f_crt.read())
            return PyOpenSSLCertSigner(key, crt)

    @staticmethod
    def _generate_pkey(key_length):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, key_length)
        return key

    @staticmethod
    def _generate_csr(pkey, domain, subj_str):
        req = crypto.X509Req()

        # subject
        subj = req.get_subject()
        ICertSigner._subj_parse(subj, subj_str)
        subj.CN = domain

        req.set_pubkey(pkey)
        req.sign(pkey, 'sha256')
        return req

    def _generate_crt(self, pkey, csr, days):
        cert = crypto.X509()

        cert.set_pubkey(pkey)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self._days_to_seconds(days))

        cert.set_issuer(self._ca_crt.get_subject())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.sign(self._ca_key, 'sha256')

        return cert

    @staticmethod
    def _days_to_seconds(days):
        return 60 * 60 * 24 * days

    def sign_domain(self, domain, days, subject_str=None, key_length=4096):
        key = self._generate_pkey(key_length)
        csr = self._generate_csr(key, domain, subject_str)
        cert = self._generate_crt(key, csr, days)

        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert), \
               crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
