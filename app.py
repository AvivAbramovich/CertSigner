import flask
from signer import SubprocessScriptCertSigner, PyOpenSSLCertSigner
from argparse import ArgumentParser
from os import getenv
import zipfile
import logging
import io

app = flask.Flask(__name__)


def as_html(string):
    return '<html><body><div>{}</div></body></html>'\
        .format('<br>'.join(string.split('\n')))


def help_string():
    c = app.config
    return '''
        Example:
            return zip file with cert.pem and key.pem:
            GET {url}?q=my.domain.com
        
            returns as text:
            GET {url}?q=my.domain.com&as-text
            
            more optional args:
            key_len: the key length (default: {key_len})
            days: number of days for certificate to be valid (default: {days})
            subj: subject string (default: {subj})
    '''.format(url=flask.request.url, days=c['days'], key_len=c['key_len'], subj=c['subj'])


def as_zip(d):
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, mode='w') as z:
        for key, val in d.items():
            z.writestr(key, val)
    mem.seek(0)
    return mem


@app.route('/')
def sign_domain():
    args = flask.request.args
    domain = args.get('q')
    subject = args.get('subj', app.config['subj'])
    key_len = int(args.get('key_len', app.config['key_len']))
    days = int(args.get('days', app.config['days']))

    if not domain:
        flask.abort(400, 'No q argument\n' + help_string())
    as_text = False if flask.request.args.get('as-text') is None else True
    try:
        app.logger.info('Signing "{d}" (days: {days}, key_len: {kl}, subj: {subj})'.format(
            d=domain, days=days, kl=key_len, subj=subject))
        crt, key = app.config['signer'].sign_domain(domain, days, key_length=key_len, subject_str=subject)
    except Exception as e:
        app.logger.exception(e)
        flask.abort(500, 'Failed to sign domain "{}": {}'.format(domain, str(e)))
    else:
        if as_text:
            return as_html(crt.decode('utf-8') + '\n\n' + key.decode('utf-8'))
        else:
            d = {'cert.pem': crt, 'key.pem': key}
            f = as_zip(d)
            return flask.send_file(f, attachment_filename='{}.zip'.format(domain),
                                   as_attachment=True)


if __name__ == '__main__':
    args_parser = ArgumentParser()
    args_parser.add_argument('--ca_crt', help='path to CA cert', default=getenv('CA_CRT'))
    args_parser.add_argument('--ca_key', help='path to CA private key', default=getenv('CA_KEY'))
    args_parser.add_argument('--key_len', help='the default private key length', type=int, default=int(getenv('KEY_LEN', 4096)))
    args_parser.add_argument('--subj', help='default subject', default=getenv('SUBJ'))
    args_parser.add_argument('--days', help='days for certificate', type=int, default=int(getenv('DAYS', 3650)))
    args_parser.add_argument('-p', help='listening port', type=int, default=80)
    args_parser.add_argument('--log_level', help='log level', default='INFO')
    args = args_parser.parse_args()

    signer = PyOpenSSLCertSigner.create_from_paths(args.ca_key, args.ca_crt)
    app.config['signer'] = signer
    app.config['key_len'] = args.key_len
    app.config['subj'] = args.subj
    app.config['days'] = args.days

    app.logger.level = logging.getLevelName(args.log_level)

    app.run(host='0.0.0.0', port=args.p)
