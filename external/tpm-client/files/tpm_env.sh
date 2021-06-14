#!/bin/sh
tpm_server &
tpm2-abrmd --tcti=mssim --allow-root &
modprobe octopos-tpm &