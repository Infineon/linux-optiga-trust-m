#!/bin/bash
source config.sh


rm *.pem

set -e


echo "Install tools:-----> Installing CURL and NGINX"
sudo apt-get install -y nginx curl
