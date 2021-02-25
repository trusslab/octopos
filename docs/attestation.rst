=======================
OctopOS TPM Attestation
=======================

:Author: - Mingyi Chen <mingyic4@uci.edu>

The built-in remote attestation using Trusted Platform Module (TPM) in OctopOS.

Attestation Process
===================
This is a test stage implementation. So there are some differences comparing with the real attestation process.

1. The client-side attestor connects to the remote-side verifier.
2. Verifier send a nonce to the attestor.
3. The attestor receive the nonce, quote it and send the signature and log to the attestor.
4. The attestor validate the signature and log.

No Certificate Authority (CA) will participate in the attestation process now.

Run Attestation
===============
After compiling the OctopOS, you can run the remote-side application:

$ sudo ./applications/attest_client/attest_server

And then run the attest_client in the OctopOS. If it works, you can type the PCR slot you want to verify in the remote-side application.


Potential Problems
==================
Problem 1. No validation in the remote-side application.
Answer: The validation in the remote-side application is now disabled for there is no logs in the extend process.
