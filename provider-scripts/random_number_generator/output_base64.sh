#!/bin/bash
set -exo pipefail

openssl rand -provider trustm_provider -base64 32
