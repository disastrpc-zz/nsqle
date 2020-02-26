# nsqle
## Injection tool for NoSQL database engines

This tool tests POST/GET parameters for injections, then attempts to retrieve user names and passwords by injecting regex strings into the query.

## Examples:
```
nsqle -r POST -U user -P passwd -x login:login -t user http://target.com/login.php
nsqle -r GET -x login:login,session:session -P pass -t pass -o /root/pass_enum.txt https://target.com/
```
## Usage:
```
nsqle.py [OPTIONS] http(s)://mywebsite.com/

Options:
  -r, --request [POST|GET]      Choose request type  [default: POST]
  -U <str>                      Name of the username parameter  [default: username]
  -P <str>                      Name of the password parameter  [default: password]
  -x, --extra-params <key:val>  List of other parameters contained in the URL
                                separated by commas
  -t, --target <str>            Specify parameter to enumerate  [required]
  -o, --output <path>           Output results to .txt file for use with other
                                tools
  --help                        Show this message and exit.
```
