====================
OctopOS I/O Protocol
====================

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

I/O services in OctopOS need to follow a specific protocol. In the current prototype, the following services have implemented the protocol.

- Bluetooth

Fundamental Concept
===================
The key concept in the protocol is a resource. Each I/O service views its underlying I/O device as one or more resources. For example, in the case of the bluetooth service, each bluetooth device is a resource. In the case of storage, each partition is a resource. And in the case of network, each port is a resource.

The protocol is a set of operations that the service implements in order to allow the OS to allocate these resources for the apps to use in a secure fashion.

Operations
==========

#1 IO_OP_QUERY_ALL_RESOURCES

This operation allows the client (of the service) to query all resources available in the service.

Rules:

This operation is not usable if a resource is bound (see IO_OP_BIND_RESOURCE).

If authentication is used, this operation returns the TPM measurements used as authentication keys for all resources.

#2 IO_OP_CREATE_RESOURCE

This operation allows the client to create a new resource. Not all I/O services may support this as in some cases the resources might be fixed (or determined by the hardware itself). For persistent resources, this operation allows programming the expected TPM PCR measurements of the authenticated clients.

Rules:

This operation is not usable if a resource is bound (see IO_OP_BIND_RESOURCE).

If a resource is non-persistent, it will be deleted upon the reset of the service.

If a resource is persistent, the service needs to decide how it can be destroyed. There are several options. One option is to set a time-out. Another option is to allow the owner (see IO_OP_AUTHENTICATE) to destroy it. Another option is to allow the owner or some master app to destroy it (note that the owner can query this and decide whether this is right for them or not).

Expected TPM PCR measurements can be programmed only if none already exists for that resource.

#3 IO_OP_BIND_RESOURCE

This operation allows the client to bind one or more resources to the service queues, allowing the client to use them. In practice, we expect the OS to use this operation before delegating the I/O service queues to a runtime processor or the untrusted domain, which can then use the bound resources (but no other resources).

Rules:

No new resources can be bound if some resources are already bound.

A bound resource cannot be unbound until the service is reset.

#4 IO_OP_QUERY_STATE

This operation allows the client to query the state of the I/O service.

The query response includes the following information:

Is any resource bound?

Has the service been used since it was reset? Using a service refers to issuing any of the operations other than QUERY_ALL_RESOURCES, CREATE_RESOUCE, and BIND_RESOURCE.

If bound, what are the bound resource names?

Any service specific information? For example, for persistent states that need authentication, the query response includes the expected TPM PCR measurements of the authenticated clients.

Rules:

If authentication is needed for a resource, then this operation is allowed only if the client has successfully authenticated.

#5 IO_OP_AUTHENTICATE

This operation allows the client to authenticate with the service. We use the TPM PCR measurement of the client for authentication. As part of this operation, the client can also send a signature to the service. This is needed when the serivce wants to restrict its usage to approved clients. The signature is by a trusted entity, which signs the expected PCR measurement of the client.

Rules:

This operation is only allowed if some resources are bound.

This operation returns an error if the client successfuly authenticated before.

When a service needs authentication, it should reject servicing the following operations before a successful authentication: QUERY_STATE, SEND_DATA, RECEIVE_DATA, DEAUTHENTICATE, and DESTROY_RESOURCE.

#6 IO_OP_SEND_DATA

#7 IO_OP_RECEIVE_DATA

These two operations are used by the client to send/receive data to/from the service.

Rules:

These operations are only allowed if some resources are bound.

If authentication is needed, then these operations are allowed only if the client has successfully authenticated.

#8 IO_OP_DEAUTHENTICATE

This operation allows the client to deauthenticate with the service.

Rules:

This operation is only allowed if some resources are bound.

This operation is only allowed if the client successfuly authenticated before.

#9 IO_OP_DESTROY_RESOURCE

This operation allows the client to destroy a resource. This operation is used for persistent resources as non-persistent ones are destroyed upon the reset of the service.

Rules:

This operation is only allowed if some resources are bound.

If authentication is needed, then this operation is allowed only if the client has successfully authenticated.

After a resource is destroyed, it cannot be used for SEND_DATA, RECEIVE_DATA, AUTHENTICATE, and DESTROY_RESOURCE. When authentication is used, the resource needs to be deauthenticated.
