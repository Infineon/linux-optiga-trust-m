#!/bin/bash
set -exo pipefail

openssl pkeyutl -provider trustm_provider -provider default -verify -pubin -inkey e0f3_pub.pem -rawin -in test_sign.txt -sigfile test_sign.sig
