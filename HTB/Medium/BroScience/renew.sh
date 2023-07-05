#!/bin/bash 

#openssl x509 -in $1 -noout -checkend 86400 > /dev/null
openssl x509 -in $1 -noout -subject | cut -d "=" -f2-