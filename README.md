# OpenID Connect Gatekeeper for Istio
This project creates a standalone OpenId Connect Gatekeeper that will handle login, logout to an OIDC provider and protect certain routes via an istio extension provider. The gatekeeper acts as a confidential client and handles code exchange and token refresh automatically. The session information is kept either in an encrypted secure HTTP-only cookie or in a memory or encrypted redis storage at the backend. The istio extension provider will verify the token and send the access token upstream to the destination.

It can protect any type of server side resources, such as API:s, static webpages and can also be used by SPA:s to make it simpler to handle authentication and authorization.

**NOTE!** This is work in progress and have some thing that needs to be done and quirks to solve before it is production ready. But it is fully functional for experimental use for now.

## Introduction
It is used by istios authorization policy as a CUSTOM action and acts as a confidential client. For each HTTP request it looks up the session information, either in backend storage or as a cookie in the incoming request. It extracts the access token from the session information and sends it upstream (**Authorization: Bearer xxxx** header).

It also provides three endpoints for logging in, callback from the login and logout. It handles the OIDC providers interface and creates the cookies and backend storage of the session information.

### Runtime and development versions
The following versions are used for runtime, development and testing. It might work perfectly fine with other versions as well but it has not been verified.
* Keycloak 21.1.1 (keycloak-authz-client, keycloak-core)
* Istio 1.17.2/1.18.2
* Quarkus 3.2.0

### Things to add or do
* Performance tuning and deployment scenarios.
* Add and option for fine grained authorization in the same ways as [Authz](https://github.com/dnulnets/authz)

## Kubernetes setup

### External extension provider
Istio has to be configured with the extension provider to be able to use it as a CUSTOM action.

```
kubectl edit configmap istio -n istio-system
```
Add the extension provider as shown below and make sure to include the headers both up and down stream to ensure the correct cookie and authorization handling.
```
data:
  mesh: |-
    defaultConfig:
      discoveryAddress: istiod.istio-system.svc:15012
      proxyMetadata: {}
      tracing:
        zipkin:
          address: zipkin.istio-system:9411
    enablePrometheusMerge: true
    rootNamespace: istio-system
    trustDomain: cluster.local
    extensionProviders:
    - name: "simple-ext-authz-http"
      envoyExtAuthzHttp:
        service: "authz.simple.svc.cluster.local"
        port: "8080"
        includeRequestHeadersInCheck: ["cookie"]
        headersToUpstreamOnAllow: ["authorization", "cookie"]
        headersToDownstreamOnDeny: ["set-cookie"]
        headersToDownstreamOnAllow: ["set-cookie"]
  meshNetworks: 'networks: {}'
```

### Example AuthorizationPolicy
This example shows how to use an authorization policy for the "app" **simple**. You want to protect it using a CUSTOM action that specifies the previous added extension provider to use for authorization. The provider has to be set up in advance. See previous chapter.
```
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: ext-authz
spec:
  selector:
    matchLabels:
      app: simple
  action: CUSTOM
  provider:
    name: simple-ext-authz-http
  rules:
  - to:
    - operation:
        paths: ["*"]
```

## Deployment of the extension provider

## Setup in keycloak

## How to build it
### Building the docker image
It is published on docker hub as dnulnets/oidcgk, but if you want to build it on your own it can be done with the following command.

```
quarkus build -Dquarkus.container-image.build=true
```
