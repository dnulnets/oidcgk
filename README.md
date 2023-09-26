# OpenID Connect Gatekeeper acting as PDP for Istio (or other PEP)
This project creates a standalone OpenId Connect Gatekeeper that will handle login and logout to an OIDC provider and acts as a PDP, Policy Decisionion Point, for istio or any other PEP, Policy Enforcement Point, that can consume the PDP:s API.


The gatekeeper acts as a confidential client and uses the authorization code flow. It handles code exchange and token refresh automatically. The session information is kept either in an encrypted secure HTTP-only cookie or in a memory or encrypted redis or infinispan storage at the backend. The PDP can act as an istio extension provider and will verify the session and send the access token together with the decision to the PEP. The PEP can then decide to sent it further downstrean to the destination.


The gatekeeper can protect any type of server side resources, such as API:s, static webpages and can also be used by SPA:s to make it simpler to handle authentication and authorization.

**NOTE!** This is work in progress but it is fully functional for experimental use for now.

## Introduction
For each HTTP request the gatekeeper looks up the session information and extracts the access token. It then sends it upstream to the final
destination (**Authorization: Bearer xxxx** header). It also refreshes the access token if needed.

The gatekeeper provides three endpoints. One for logging in and the callback from the login and one for logging out. It handles the OIDC providers authentication and authorization endpoints, cookies and backend storage for the session information.

### Session information
The session information contains the session id, the access token, the refresh token and the id token. If stored in the browser it is encrypted with the gatekeepers keys, and if stored in the backend it is encrypted with a random generated key stored in a cookie and is unique for the session.
### The use of cookies and backend storage
The gatekeeper relies on the use of secure HTTP-only cookies and it uses them in two different ways depending on the selected method for storage.
#### Browser storage
In browser storage mode i.e. **browser**, the entire session information is stored in the cookies. No backend storage is used.
* The drawback is that the requests from the browser can be really big because of the cookies size.
* The advantage is that you will need no backend storage and you can easily load balance between multiple gatekeepers.
#### Backend storage
In backend storage mode i.e. **memory**, **redis** or **infinispan**, a session identifier and the backend storage encryption key is stored in the cookies. The actual session information is stored in the backend. 
* The advantage is that the size of the requst from the browser will be small.

Currently there are three different backend storages implemented:
* **memory**, which do not require any external storage.
  * The drawback is that the sessions will not survive a restart of the server and if using more than one gatekeeper to load balance between you need to use sticky sessions.
  * The advantage is that it is easily configured for the backend.
* **redis**, which requires an external Redis-server.
  * The drawback is that it is more cumbersome to set up.
  * The advantage is that the sessions will survive a restart.
* **infinispan**, which requires an external infinispan-server.
  * The drawback is that it is more cumbersome to set up.
  * The advantage is that the sessions will survive a restart.

### Endpoints

#### /oidc/login
This is the login endpoint that is used whenever an application wants to authenticate the user. If the browser has no valid session the gatekeeper will redirect the browser to the authorization endpoint of the OIDC provider and reqeust a new code. Upon successfull login the provider will redirect the browser back to the **/oidc/callback** endpoint at the gatekeeper.

#### /oidc/callback
When the user has successfully logged in at the OIDC provider it will redirect the browser to this endpoint where the gatekeeper exchanges the code for an access token, refresh token and id token with the providers token endpoint. It then creates the complete session information and stores it.
#### /oidc/logout
This endpoint logs out the user and destroys the session information.
#### /*
This endpoint is the PDP and verifes the session information, extract the access token and refreshes it with the OIDC provider if needed. The token is also sent back in the response as an **authorization**-header and any **set-cookie**-headers with a 200 OK if it will allow it to proceed.

### Runtime and development versions
The following versions are used for runtime, development and testing. It might work perfectly fine with other versions as well but it has not been verified.
* Keycloak 21.1.1 (keycloak-athz-client, keycloak-core)
* Istio 1.17.2/1.18.2
* Quarkus 3.2.0

### Things to add or do
* Performance tuning and deployment scenarios.
* Add and option for fine grained authorization in the same ways as [Authz](https://github.com/dnulnets/authz) for the istio extension authorization.
* Do not allow any redirect_uri for the login endpoint.

## Kubernetes setup

### External extension provider
Istio has to be configured to use the gatekeeper as the extension provider to be able to use it as a CUSTOM action in the AuthorizationPolicy.

```
kubectl edit configmap istio -n istio-system
```
Add the gatekeeper as the extension provider shown below and make sure to include the headers for both up and down stream to ensure the correct cookie and authorization handling.
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
This example shows how to use an authorization policy for the "app" **simple**. You want to protect it using a CUSTOM action that specifies the previous added extension provider to use for authorization.
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

## Deployment of the gatekeeper
### Configuring the gatekeeper
The configuration is stored in the application.properties file.
#### Base configuration (oidc.base)
Contains configuration for the behaviour of the gatekeeper.
|Property|Description|Default |
|---|---|---|
|oidcgk.base.url|The base url for the gatekeepe. Used e.g. when creating the callback url|None| 
|oidcgk.base.aad|Additional authentication data used during encryption and decryption when storing the session in the browser.|OpenID Connect Gate Keeper Version 0.1|
|oidcgk.base.storage|Specifies how the session information is stored. It can be either **browser**, **memory**, **redis** or **infinispan**. **browser** and **memory** do not require any additional configuration.|None|
|oidcgk.base.storage.TTL|Specifies the time to live for the session in the backend storage in seconds.|1800|

#### Application specific configuration (oidcgk.application)
Contains configuration for the application protected by the gatekeeper.
|Property|Description|Default |
|---|---|---|
|oidcgk.application.url|The application url that the gatekeeper redirects to after successful login.|None| 

#### OIDC Provider (oidcgk.oidc)
Contains configuration for where the OIDC provider is located and which realm and client to use during authentication.
|Property|Description|Default |
|---|---|---|
|oidcgk.oidc.url|The URL to the OIDC providers well known configuration information.|None|
|oidcgk.oidc.realm|The realm to use during authentication|None|
|oidcgk.oidc.client|The confidential client to use during configuration|None|
|oidcgk.oidc.secret|The secret of the confidential client.|None|
|oidcgk.oidc.audience|The audience required in the token when authenticated.|None|

#### Cookie configuration (oidcgk.cookie)
The configuration of the cookies used for storage.
|Property|Description|Default |
|---|---|---|
|oidcgk.cookie.name|The base name of the cookie, used for all the cookies created by the gatekeeper.|oidcgk|
|oidcgk.cookie.domain|The domain of the cookie.|None|
|oidcgk.cookie.path|The path of the cookie.|/|
|oidcgk.cookie.maxAge|The maximum age of the cookies.|10800|
|oidcgk.cookie.key|The key used when encrypting and decrypting the cookies|None|

#### Redis configuration
The configuration of the redis client. Only useful if the storage **redis** is selected. See the quarkus documentation on all of the configuration properties of the redis client.
|Property|Description|Default |
|---|---|---|
|quarkus.redis.oidcgk.hosts|The URL to the redis server. It must be of the format **redis://my-redis:6379**|None|

#### Infinispan configuration
The configuration of the infinispan client. Only useful if the storage **infinispan** is selected. See the quarkus documentation on all of the configuration properties of the infinispan client.
|Property|Description|Default |
|---|---|---|
|quarkus.infinispan-client.uri|The URL to the infinispan cluster. it must be of the format **hotrod://admin:password@infinispan:11222**.|None|
|quarkus.infinispan-client.username|The username for the infinispan cluster|None|
|quarkus.infinispan-client.password|The password for the infinispan cluster|None|
|quarkus.infinispan-client.cache.oidcgk.configuration|Configuration for the cache. It must at least be this value. **&lt;distributed-cache&gt;&lt;encoding media-type="text/plain"/&gt;&lt;/distributed-cache&gt;**|None|
|quarkus.infinispan-client.client-intelligence|The client behaviour. Should at least be **BASIC**|None|

## How to build it
### Docker hub
The image is published on docker hub, see [Docker image](https://hub.docker.com/r/dnulnets/oidcgk).
### Building the docker image
You can build it on your own with the following command:

```
quarkus build -Dquarkus.container-image.build=true
```
