#!/bin/bash
set -exo pipefail

openssl rand -provider trustm_provider -hex 32
