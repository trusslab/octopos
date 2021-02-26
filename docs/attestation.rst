=======================
OctopOS TPM Attestation
=======================

:Authors: - Mingyi Chen <mingyic4@uci.edu>
          - Ardalan Amiri Sani <arrdalan@gmail.com>

The built-in remote and local attestations using Trusted Platform Module (TPM) in OctopOS.

Remote Attestation Process
==========================
This is a test stage implementation. So it will have some differences with the true attestation process.

1. The client-side attestor connects to the remote-side verifier.
2. Verifier send a nonce to the attestor.
3. The attestor receive the nonce, quote it and send the signature and log to the attestor.
4. The attestor validate the signature and log.

No Certificate Authority (CA) will participate in the remote attestation process now.

Run Example Remote Attestation App
==================================
After compiling the OctopOS, you can run the example remote-side server:

$ sudo ./applications/attest_client/attest_server

And then run the attest_client in the OctopOS. If it works, you can type the PCR slot you want to verify in the remote-side server.

Potential Problems with Remote Attestation
==========================================
Problem 1. No validation in the remote-side application.
Answer: The validation in the remote-side application is now disabled for there is no logs in the extend process.

Local Attestation
=================
At the time of remote attestation, the app might not have secure access to I/O services that it will need to use. The app uses local attestation for this purpose. More specifically, after a successful remote attestation, it asks the remote-side server for the expected measurements of the code in I/O services. It then uses these expected measurements to compare with the ones it directly acquires from the TPM.

Two notes:

1. Local attestation of the network service requires care. This is because the app first needs to use the network service to communicate with the remote-side server. The app and server must not share any secrets before the app performs local attestation of the network service. Note that we assume that the app and server use a secure network protocol such as TLS, which can help with integrity and authenticity of the messages. The goal of local attestation of the network service is to ensure strict confidentiality (which TLS cannot guarantee due to side channels available through network traffic analysis).

2. Local attestation of the storage service requires some attention as well. The storage service might be used by an app to store secrets, so that the app does not need to contact its server in future runs. As a result, in future runs, the app cannot securely perform local attestation of the storage service. However, in some cases, this might be okay. An example of this is the sample health_client app. In this case, without accessing the secret in the correct storage service (which is the password needed to authenticate with the insulin pump), no damage can be done if a malicious storage service is provided to the app.
