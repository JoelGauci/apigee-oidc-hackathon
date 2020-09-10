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
... then from a terminal:
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
kubectl create -f https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/latest/kubernetes-examples/keycloak.yaml
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
 $ template=`cat ingress.yaml`
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

### testing our keycloak configuration

For this, we need endpoints information regarding our keycloak IdP...

You can access the **list of exposed endpoints** (+some other info) using the following URL:

```https://$KEYCLOAK_HOST_NAME/auth/realms/demo/.well-known/openid-configuration```

If you invoke this URL using a REST client (like [hoppscotch.io](https://hoppscotch.io/)), you should see a response like this one (I just provide an extract of the JSON response):

```
{
  "issuer": "https://a.b.c.d.xip.io/auth/realms/master",
  "authorization_endpoint": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/auth",
  "token_endpoint": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/token",
  "introspection_endpoint": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/token/introspect",
  "userinfo_endpoint": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/userinfo",
  "end_session_endpoint": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/logout",
  "jwks_uri": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/certs",
  "check_session_iframe": "https://a.b.c.d.xip.io/auth/realms/master/protocol/openid-connect/login-status-iframe.html",
  "grant_types_supported": [
    "authorization_code",
    "implicit",
    "refresh_token",
    "password",
    "client_credentials"
  ],
  "response_types_supported": [
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
```
... where ```a.b.c.d.xip.io``` is your valid keycloak hostname!

In order to quickly test your configuration, execute the following URL into your Chrome Web browser:

```
https://$KEYCLOAK_HOST_NAME/auth/realms/demo/protocol/openid-connect/auth?client_id=my-client-app&response_type=code&state=blablabla&redirect_uri=https://localhost/redirect
```

You will be redirected to the login page of keycloak demo realm:

<img src="./pictures/_G.png" width="500">

Use the end user's login and password (my user is *jeanmartin*)
Once authenticated, you may have to modify the user's password - as it is your first connection:

<img src="./pictures/_H.png" width="500">

Once authenticated, you reach the consent page (default one w/ keycloak logo). 

As an authenticated user you can (or not) give the client app (**my-client-app**) access to some of your user information: user profile, email address, user roles... so make the right choice !

If you give your consent you are redirected (```HTTP 302```) to the client app redirect URI: ```https://localhost/redirect```

Look at the query parameters provided on this redirection URL... you should see an **authorization code** (```code=xxx```). This code would be used by the client app to access a valid JWT token that would contain an OAuth2.0 access token:

```
https://localhost/redirect?state=blablabla&session_state=2a7f170b-c3db-4e10-858b-2a2559eaf060**&code=8b773b67-df66-4cd0-a271-4dcf53b723d8.2a7f170b-...-214**
```

The basic keycloak configuration is now in place!!! **Well done!**


