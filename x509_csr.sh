#!/bin/bash

openssl req -new -subj "/C=US/ST=MI/L=Detroit/O=Schneider/OU=Unit/CN=Ash Gupta/emailAddress=guptashark@protonmail.comm"  -key sample.pem -out cmd_gen.csr
