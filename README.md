# apigee-oidc-hackathon

![](https://curity.io/images/resources/tutorials/integration/tutorials-apigee.png)

## Welcome to the Apigee OIDC Hackathon!!!

### introduction
The main goal of this hackathon is to demonstrate - through some real examples - the security capabilities of Apigee (https://cloud.google.com/apigee) regarding **end-user Authentication for API access based on OIDC** (OpenID Connect)

### pre-requisites
In this hackathon, we will use the following solutions:
1. [keycloak](https://www.keycloak.org/) as an Identity Provider (IdP): we will use a free docker image of keycloak
1. [Google Cloud Platform](https://cloud.google.com/) - aka GCP -to leverage a kubernetes cluster, on which keycloak will be installed
1. Apigee Edge for Public Cloud: you can subscribe for a trial account [here](https://login.apigee.com/sign__up)
1. [Maven](https://maven.apache.org/) for the deployment of the Apigee technical artifacts on your target Apigee platform (SaaS)
1. [openssl](https://www.openssl.org/) to be able to create cryptographic objects for TLS communications

![](https://janikvonrotz.ch/images/keycloak-logo.png)
![](https://www.fxinnovation.com/wp-content/uploads/2019/03/Google-Cloud-Logo1.png)
![](https://deertek.files.wordpress.com/2018/09/9.png?w=200)

### steps
Here a re the different steps we will complete in the hackathon
1. install keycloak on a Google Kubernetes Engine (GKE) cluster 
1. configure a simple Client App and user in keycloak
1. deploy an API Proxy on Apigee that is able to secure APIs - based on OIDC. All the material is provided on the repo

## step-1: keycloak installation (~15')
We are going to make it as simple as possible...do not forget that our goal is to understand OIDC concepts and security configuration in Apigee, not to spend our lives installing keycloak...

Let's consider that the installation of keycloak will not only be used for this hackathon. After the event, you will probably be interested in digging into the meanders of OAuth2.0 and OIDC in Apigee ;-)

This is why we are going to set a static IP address in GCP, that we can use on an ingress to access our keycloak platform

So at this step, please:
1. connect to your GCP console
2. create a project or use an existing one
... then from a terminal (and from the root of the cloned repo):

```
$ gcloud update
$ gcloud init
```

We need a kubernetes cluster so let's create it!
```
$ export CLUSTER_NAME=keycloak-cluster
$ gcloud container clusters create $CLUSTER_NAME --num-nodes 3 --machine-type n1-standard-1
```
The ```keycloak-cluster``` is the cluster we use to provision the keycloak platform.

The creation process should last 2 to 3 minutes...during this time we can create a static IP address.
For more details, you can refer to the GCP online documentation on **[how to reserve an external static IP address](https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address)**

Here is the command to create your static IP address:

```
$ gcloud compute addresses create keycloak-ingress-lb \
    --global \
    --ip-version IPV4
```
```keycloak-ingress-lb``` is the address's name of the IP for your ingress keycloak loadbalancer

To view the resulting IP address, use the following command:
```
$ export ADDRESS_NAME=keycloak-ingress-lb
$ echo $ADDRESS_NAME # for simple verification...
$ gcloud compute addresses describe $ADDRESS_NAME
```
select ```global``` and note the static IP address that is returned (we call it {STATIC_IP_ADDRESS})

As we want a hostname to access the keycloak UI, we have the interesting option to use [xip.io](https://xip.io/): xip.io is a domain name that provides wildcard DNS
for any IP address. As an example, the host ```a.b.c.d.xip.io``` is resolved to ```a.b.c.d```

We will use this type of hostname and our static IP address when configuring the ingress load balancer

export the keycloak hostname environment variable:

```
$ export KEYCLOAK_HOST_NAME={STATIC_IP_ADDRESS}.xip.io
$ echo $KEYCLOAK_HOST_NAME
```

At this time, please check that your kubernetes cluster has been created. Set the current context to your newly created cluster, where the name of the context is made up of gke_ plus project-id, your GCP project ID, compute-zone, and the name of the new cluster, separated with underscores (_):

```
$ kubectl config use-context gke_{project-id}_{compute-zone}_$CLUSTER_NAME
```
Check the current context to be sure it is set to the intended cluster:

```
$ kubectl config current-context
```

Now that your cluster has been created and your gcloud context has been set, you can deploy keycloak on the target cluster:

```
kubectl create -f ./k8s/keycloak.yaml
```
This will start Keycloak on Kuberneters. It will also create an initial **admin** user with username ```admin``` and password... ```admin``` ;-)

Let's create crypto objects for the ingress (private key and self-signed certificate) that we can use to access the keycloak UI. For this we use the "*.xip.io" common name (CN):

```
$ openssl req -x509 -out tls.cert -keyout tls.key -newkey rsa:2048 -nodes -sha256 -subj '/CN=*.xip.io' -extensions EXT -config <( printf "[dn]\nCN=*.xip.io\n[req]\ndistinguished_name=dn\n[EXT]\nbasicConstraints=critical,CA:TRUE,pathlen:1\nsubjectAltName=DNS:*.xip.io\nkeyUsage=digitalSignature,keyCertSign\nextendedKeyUsage=serverAuth")
```

Create the kubernetes secret for the ingress:
```
$ kubectl create secret tls tls-secret --cert=tls.cert --key=tls.key
```

Create the ingress that will be the entry point to access the keycloack UI (```ingress.yaml``` is provided in the repo):
```
 $ template=`cat ./k8s/ingress.yaml`
 $ set -e
eval "cat <<EOF
$template
EOF
" | kubectl create -f -
 
```
Verify that the ingress has been created:
```
$ kubectl get ingress
```
...the ADDRESS field should be provisioned in less than 5 minutes

From there you can access your keycloak UI using the following URL in your favorite Web brower (Chrome!): 
```
https://$KEYCLOAK_HOST_NAME
```
Accept the connection even if you see a ERR_CERT_AUTHORITY_INVALID error on your Web browser (remember the cert is self-signed!)

Now you should see the keycloak admin console!!! **Well done!**

<img src="./pictures/_1.png" width="500">

The hackathon goes on with some basic keycloak configuration steps and a test

## step-2: basic keycloak configuration (~10')
In this second step we will configure keycloak as an IdP (identity provider)

The 3 main steps of the configuration are:
1. create a dedicated keycloak **realm** for the purpose of the test
2. create a **client app**
3. create an **end user**

I will not provide configuration details (still remember what is our goal?) but all screenshots provide the information you need to execute what needs to be done

Just login to your keycloak admin console using the **admin** account (login: ```admin``` - password: ```admin```)

<img src="./pictures/_2.png" width="300">

### create a demo realm

Add a realm, name it ```demo```:

<img src="./pictures/_3.png" width="400">

<img src="./pictures/_4.png" width="400">

You can access the ```demo``` realm settings:

<img src="./pictures/_5.png" width="500">

### create a client app

Access the **Clients** configuration panel:

<img src="./pictures/_6.png" width="550">

Create a new client app (```my-client-app```)

<img src="./pictures/_7.png" width="400">

Modify/configure properties as defined in the following picture:

<img src="./pictures/_8.png" width="600">

> Important: **Access Type** set to ```confidential```, **Consent Required** set to ```on```, **Valid Redirect URIs** set to ```https://localhost/redirect```

Keep default values for client scopes:

<img src="./pictures/_9.png" width="600">

### create an end user

We finalize the keycloak configuration creating an end user

Access the **Users** configuration panel and add a user (there is a button for that;-):

<img src="./pictures/_A.png" width="550">

Define **username**, **email** and **required user actions**:

<img src="./pictures/_B.png" width="600">

Please use values of your convenience...

From the **Credentials** tab, set the user's password: 

<img src="./pictures/_C.png" width="600">

Confirm that you want to set password for the user:

<img src="./pictures/_D.png" width="400">

Later, you will be able to check user's consent from the **Consents** tab:

<img src="./pictures/_E.png" width="500">

The basic configuration we want to implement is over! Let's test it quickly!

### keycloak configuration testing

For this, we need endpoints information regarding our keycloak IdP...

You can access the **list of exposed endpoints** (+some other info) using the following URL:

```https://$KEYCLOAK_HOST_NAME/auth/realms/demo/.well-known/openid-configuration```

If you invoke this URL using a REST client (like [hoppscotch.io](https://hoppscotch.io/)), you should see a response like this one (I just provide an extract of the JSON response):

<pre><code>
{
  <b>"issuer"</b>: "https://a.b.c.d.xip.io/auth/realms/master",
  <b>"authorization_endpoint"</b>: "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/auth",
  <b>"token_endpoint"</b>: "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/token",
  <b>"introspection_endpoint"</b>: "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/token/introspect",
  <b>"userinfo_endpoint"</b>: "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/userinfo",
  <b>"end_session_endpoint"</b>: "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/logout",
  <b>"jwks_uri"</b>: "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/certs",
  "check_session_iframe": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/login-status-iframe.html",
  <b>"grant_types_supported"</b>: [
    "authorization_code",
    "implicit",
    "refresh_token",
    "password",
    "client_credentials"
  ],
  <b>"response_types_supported"</b>: [
    "code",
    "none",
    "id_token",
    "token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token"
  ],
  ...
</code></pre>

... where ```a.b.c.d.xip.io``` is your valid keycloak hostname!

In order to quickly test your configuration, execute the following authorization URL into your Chrome Web browser (replace $KEYCLOAK_HOST_NAME with your own value):

<pre><code>
https://$KEYCLOAK_HOST_NAME/auth/realms/demo/protocol/openid-connect/auth?<b>client_id=my-client-app</b>&<b>response_type=code</b>&state=blablabla&<b>redirect_uri=https://localhost/redirect</b>
</code></pre>

> Important: **client_id**, **response_type** and **redirect_uri** are required query parameters. It is also a best practice to provide a **state** parameter

You will be redirected to the login page of keycloak demo realm:

<img src="./pictures/_G.png" width="500">

Use the end user's login and password (my user is *jeanmartin*)
Once authenticated, you may have to modify the user's password - as it is your first connection:

<img src="./pictures/_H.png" width="500">

Once authenticated, you reach the consent page (default one w/ keycloak logo):

<img src="./pictures/_I.png" width="500">

As an authenticated user you can (or not) give the client app (**my-client-app**) access to some of your protected user information: user profile, email address, user roles... so make the right choice !

If you give your consent you are redirected (```HTTP 302```) to the valid client app redirect URI: ```https://localhost/redirect```

Look at the query parameters provided on this redirection URL... you should see an **authorization code** (```code=xxx```). This code would be used by the client app to access a valid JWT token that would contain an OAuth2.0 access token:

<pre><code>
https://localhost/redirect?state=blablabla&session_state=2a7f170b-c3db-4e10-858b-2a2559eaf060&<b>code</b>=8b773b67-df66-4cd0-a271-4dcf53b723d8.2a7f170b-...-214
</code></pre>

The very last step, before deploying Apigee artifacts is to store the client secret of ```my-client-app``` into a dedicated environment variable:

Please go back to the **Clients** section of your keycloak UI and select your client (```my-client-app```)

Click the **Credentials** tab and copy the value of my-client-app's client secret:

<img src="./pictures/_J.png" width="500">

In your terminal, create the **APP_CLIENT_SECRET** env variable:

```
$ export APP_CLIENT_SECRET={THE_VALUE_OF_YOUR_CLIENT_SECRET}
```

Your basic keycloak configuration is now in place!!! **Well done!**

## step-3: deploy Apigee technical artifacts (~15')
Please clone the github repo of the identity hackathon if not done yet. You should be able to get all the Apigee material we will use during the hackthon

First we are going to check that all the required env variables have been defined. Indeed, we use maven to deploy config and proxy on Apigee Edge for Public Cloud and for this we need credentials...that can be set as env variables! + we want to chck that keycloak hostname and app secret have been set also !

In your terminal, at the root level of the **apigee-oidc-hackathon** directory, execute the follwing script:

```
$ ./check_envvar.sh
```

The response should be similar to the following one:

<pre><code>
<b>APIGEE_ORG</b> is set!
<b>APIGEE_USER</b> is set!
<b>APIGEE_PASSWORD</b> is set!
<b>KEYCLOAK_HOST_NAME</b> is set!
<b>APP_CLIENT_SECRET</b> is set!
</code></pre>

In case of a problem with one or several env variables, it is time to fix it!

You are now ready to deploy the Apigee technical artifacts for he hackathon. Here are the elements that will be loaded on your Apigee organization:
1. **apigee-oidc-v1**: API Proxy
2. **IdentityProduct**: API Product
3. **identityApp**: application
4. **helene.dozi.demo@gmail.com**: App developer
5. **IDP_JWKS_CACHE**: environment (*test*) cache
6. **idpConfig**: environment (*test*) KVM (Key Value Map)

The KVM contains all the parameters required to connect the keycloak IdP

Let's deploy these 6 elements:

```
$ ./pipeline.sh
```

You can follow the deployment process: ```set -x``` (in the ```pipeline.sh``` script) enables a mode of the shell where all executed commands are printed to the terminal

At the end of the build process, you should see a response/status like this one:

```
[INFO] Update Success.
[INFO] ---------
[INFO] BUILD SUCCESS
[INFO] ---------
[INFO] Total time: 22.539 s
[INFO] Finished at: 2020-09-14T18:06:16+02:00
[INFO] ---------
``` 

Take some time to connect to your Apigee organization and have a look on the different objects, which have been created.

## Apigee used as an identity proxy

OIDC allows an application to use an authority to:
- Verify end user’s identity (Signed JWT - id_token)
- Fetch end user’s profile info (UserInfo Endpoint)
- Gain limited access to end user’s data (Access token)

The Identity Provider is the server offering the authentication service. 

It combines the roles of OAuth Authorization Server & Resource Server, the resource being the End-User’s identity.

It is made of 4 Endpoints (HTTP resources) : 
 - Authorization Endpoint, 
 - Token Endpoint, 
 - UserInfo Endpoint, 
 - Redirect Endpoint.

It distributes OAuth tokens as well as an ID Token in JWT format.

In the hackathon, we use the **authorization code flow**

The URL used to initiate the authorization code flow is of the form:

<pre><code>
GET /authorize?
  <b>response_type=code</b>
  <b>&scope</b>=openid%20profile%20email%20address%20phone
  <b>&client_id</b>=s6BhdRkqt3
  <b>&state</b>=af0ifjsldkj
  <b>&redirect_uri</b>=https%3A%2F%2Fclient.example.org%2Fcb 
HTTP/1.1
Host: server.example.com
</code></pre>

The response of the authorization code flow is a redirection to the client app's callback/redirect URL, as presented here:
<pre><code>
HTTP/1.1 302 Found
Location: https://client.example.org/cb
  <b>?code=SplxlOBeZQQYbYS6WxSbIA</b>
  <b>&state</b>=af0ifjsldkj
</code></pre>

The client app uses the authorization code to get a valid access token or ID Token

When Apigee plays the role of an **identity proxy** in front of an IdP (like keycloak), here is a solution presented as a sequence diagram:

<img src="./pictures/OIDC_PKCE.png">

In this solution, a client app consumes an API using an access token. Apigee verifies the access token and extract the JWT token that hes been previously set as an attribute of the access token, during the OIDC/OAuth "*dance*":

<img src="./pictures/Apigee_identity_proxy.png" width="500">

### Deep dive into the API Proxy

At this step, we are going to connect to the ```apigee-oidc-v1``` API Proxy and activate the trace:

<img src="./pictures/_K.png" width="500">

Open your favorite Web browser and execute the following URL:

<pre><code>
https://$APIGEE_ORG-test.apigee.net/v1/oauth20/authorize?
  <b>client_id</b>=my-client-app
  <b>&response_type</b>=code
  <b>&state</b>=1234567890-ABCD
  <b>&redirect_uri</b>=https://localhost/redirect
</code></pre>

You will be redirected to your keycloak authentication page:

<img src="./pictures/_L.png" width="500">

Enter ```jeanmartin```'s login and password that you have set when creating this user

<img src="./pictures/_M.png" width="500">

You now access the consent page. The question here is simple: you have just been authenticated but do you give your consent in order for ```my-client-app`` (client application) to access your personal data (email addres, address, phone number...)?

<img src="./pictures/_N.png" width="500">

Once you have clicked yes you can see (in the web browser) that you have been redirected to an URL of the form:

<pre><code>
https://localhost/redirect?
  <b>code</b>=gj6I3rDP
  <b>&state</b>=1234567890-ABCD
</code></pre>

The redirection to the client app has been executed and an authorization code + state parameter have been pushed to the app (the redirect url intentionally uses ```localhost```)

Please copy the value of the authorization code and uses an HTTP client (cURL, postman, postwoman/hoppscotch,...) in order to POST data that will allow you retrieving a valid access token and refresh token:

<img src="./pictures/_O.png" width="500">

The response is based on a JSON content type. Here is an extract showing the type of value you should get as a response:

```
{
  ...
  "access_token": "AGwNYtp04irLlWERipYOFvVKv3bF",
  "refresh_token": "m3qnGAdq9NB3fnKFwSM4TVQ1HMXLHsZH",
  "subject.email": "jean.martin.demo@gmail.com",
  "subject.family_name": "Martin",
  "status": "approved",
  "expires_in": ...
}
```

The following Apigee traces depict what's happening on the Apigee side when the process you have just executed is performed:

First, the intial request is received by Apigee through an ```authorization``` endpoint. Apigee acts as an identity proxy:

<img src="./pictures/_P.png" width="500">

The result of this flow is a redirection to the keycloak IdP - cf. the **Location** parameter:

<img src="./pictures/_Q.png" width="500">

The keycloak IdP then redirects its authorization code and own state to the Apigee ```callback``` URL (after authentication and consent of the user):

<img src="./pictures/_R.png" width="500">

After verifications and controls a redirection is done to the client app redirection URI. Now Apigee hiddes keycloak parameters, produces its own authorization code and uses the initial state parameter (pushed by the client app):

<img src="./pictures/_S.png" width="500">

The client app uses the Apigee authorization code to get an access token, using the Apigee dedicated ```token``` endpoint (cf. the form parameters in the request body):

<img src="./pictures/_T.png" width="500">

Apigee connects to the keycloak IdP (using a ```ServiceCallout``` policy) to get a valid JWT token, as presented here:

<img src="./pictures/_U.png" width="500">

If you copy the ID token from the trace and paste it into [jwt.io](https://jwt.io/), you can see the token info decoded. 

Here is an example:

<img src="./pictures/_V.png" width="500">

User info can also be decoded from the token:

<img src="./pictures/_V1.png" width="300">

Finally, the Apigee token endpoint response can be seen in the trace. It consists of a valid JSON message that includes: access token, refresh token, token expiry,...The ID token is not presented to the client app but has been set as an attrtibute of the access token.

<img src="./pictures/_W.png" width="500">

Each time the access token will be checked on the identity proxy (Apigee) it will be possible to get the ID token attribute and inject it (or part of its info) to the backend resources

Take time to investigate the different endpoints exposed by the ```apigee-oidc-v1``` proxy but also the technical artifacts deployed on your Apigee organization.

You have reached the end of the identity hackathon!!! **Well done!**