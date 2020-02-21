#!/usr/bin/env python3


import string
import requests
import sys
import click

'''
POST
for character a-zA-Z0-9:  # try all characters from a-z, A-Z
    username[$eq]=a       # and 0-9 (dont forget special chars!)
        if response != 302:
            character += 1
        else
            save character and move to next
'''

def parse_args(h):
    a = {}
    p1 = h.split('?')
    for val in p1[1].split('&'):
        print(val)
        v = val.split('=')
        a[v[0]] = v[1]

    return p1[0], args

def test_injection(h, p):
    pass

def build_payload(h, up, pp):
    h, pa = parse_args(h)


@click.command()
@click.option('-r','--request',type=click.Choice(['POST','GET'],case_sensitive=False))
@click.option('-U','userp',default='username')
@click.option('-P','passwdp',default='password')
@click.option('-i','--injection-point','inject')
@click.argument('url')
def main(
    request='',
    userp='username',
    passwdp='password', inject, url):
    build_payload(host, userp, passwdp)

main()
