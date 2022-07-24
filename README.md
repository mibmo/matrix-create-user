# Synapse/Dendrite registration via shared secret

### Usage
```
$ ./create-user.py --help
usage: create-user.py [-h] [-a] [-p PASSWORD] [--insecure INSECURE] homeserver username secret

Dendrite user creator

positional arguments:
  homeserver            Homeserver address
  username              Username of the user
  secret                Registration secret

options:
  -h, --help            show this help message and exit
  -a, --admin           Is the user an administrator?
  -p PASSWORD, --password PASSWORD
                        Password of the user
  --insecure INSECURE   Use HTTP for requests (use only if hosted locally!)
```
