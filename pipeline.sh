#!/bin/sh
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -x 
set -e

cd ./apigee-oidc-v1

#################################
### function: set_idp_env_var ###
#################################
function set_idp_env_var() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X GET -H "Accept:application/json" https://34.120.206.146.xip.io/auth/realms/demo/.well-known/openid-configuration)
    if [ $( grep -c error <<< "$response" ) -ne 0  ]; then
        echo "$response"
        
        exit 1
    fi

    # extract data used to feed the kvm
    issuer=$( jq .issuer <<< "$response" )
    authorization_endpoint=$( jq .authorization_endpoint <<< "$response" )
    token_endpoint=$( jq .token_endpoint <<< "$response" )
    jwks_uri=$( jq .jwks_uri <<< "$response" )
    userinfo_endpoint=$( jq .userinfo_endpoint <<< "$response" )

    # set env variables for kvm (idpConfig)
    export TEST_IDP_ISSUER=`awk -F\" '{print $2}' <<< $issuer | awk -F\" '{print $1}'`
    export TEST_IDP_APIGEE_REDIRECT_URI="https://$APIGEE_ORG-test.apigee.net/v1/oauth20/callback"
    export TEST_IDP_ATZ_CODE_HOSTNAME=$KEYCLOAK_HOST_NAME
    export TEST_IDP_JWKS_HOSTNAME=$KEYCLOAK_HOST_NAME
    export TEST_IDP_USERINFO_HOSTNAME=$KEYCLOAK_HOST_NAME
    export TEST_IDP_ATZ_CODE_TO_TOKEN_ENDPOINT=`awk -F $KEYCLOAK_HOST_NAME'/' '{print $2}' <<< $token_endpoint | awk -F\" '{print $1}'`
    export TEST_IDP_ATZ_CODE_ENDPOINT=`awk -F $KEYCLOAK_HOST_NAME'/' '{print $2}' <<< $authorization_endpoint | awk -F\" '{print $1}'`
    export TEST_IDP_JWKS_ENDPOINT=`awk -F $KEYCLOAK_HOST_NAME'/' '{print $2}' <<< $jwks_uri | awk -F\" '{print $1}'`
    export TEST_IDP_USERINFO_ENDPOINT=`awk -F $KEYCLOAK_HOST_NAME'/' '{print $2}' <<< $userinfo_endpoint | awk -F\" '{print $1}'`
}

####################################################
### function: generate_post_data_app_credentials ###
####################################################
generate_post_data_app_credentials()
{
  cat <<EOF
{
  "consumerKey": "my-client-app",
  "consumerSecret": "$APP_CLIENT_SECRET"
}
EOF
}

#########################################################
### function: generate_post_data_app_identity_product ###
#########################################################
generate_post_data_app_identity_product()
{
  cat <<EOF
{ 
    "apiProducts": ["IdentityProduct"] 
}
EOF
}

########################################
### function: set_devapp_credentials ###
########################################
function set_devapp_credentials() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_app_credentials)" -u $APIGEE_USER:$APIGEE_PASSWORD -H "Content-Type:application/json" https://api.enterprise.apigee.com/v1/organizations/$APIGEE_ORG/developers/helene.dozi.demo@gmail.com/apps/identityApp/keys/create)
    if [ $( grep -c error <<< "$response" ) -ne 0  ]; then
        echo "$response"
        
        exit 1
    fi
}

####################################
### function: set_devapp_product ###
####################################
function set_devapp_product() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_app_identity_product)" -u $APIGEE_USER:$APIGEE_PASSWORD -H "Content-Type:application/json" https://api.enterprise.apigee.com/v1/organizations/$APIGEE_ORG/developers/helene.dozi.demo@gmail.com/apps/identityApp/keys/my-client-app)
    if [ $( grep -c error <<< "$response" ) -ne 0  ]; then
        echo "$response"
        
        exit 1
    fi
}

# set env variables for keycloak IdP 
set_idp_env_var
# deploy Apigee artifacts: developer, app, product cache, kvm and proxy
mvn install -Ptest -Dapigee.config.options=update
# set developer app (my-client-app) credentials with the exact same values than the one in the keycloak IdP
set_devapp_credentials
# set developer app (my-client-app) product
set_devapp_product
