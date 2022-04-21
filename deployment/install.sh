#!/bin/sh
# Install openg2p-mosip-components
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

NS=default

if [ -z $MOSIP_IDA_URL ]; then read -p "Give MOSIP IDA Url : " MOSIP_IDA_URL ; fi
if [ -z $MOSIP_IDA_DOMAIN_URI ]; then read -p "Give MOSIP IDA Domain : " MOSIP_IDA_DOMAIN_URI ; fi
if [ -z $MOSIP_IAM_TOKEN_ENDPOINT ]; then read -p "Give MOSIP IAM Token Endpoint Url : " MOSIP_IAM_TOKEN_ENDPOINT ; fi

if [ -z $MOSIP_OPENG2P_PARTNER_CLIENT_ID ]; then read -p "Give MOSIP OpenG2P Partner Client id : " MOSIP_OPENG2P_PARTNER_CLIENT_ID; fi
if [ -z $MOSIP_OPENG2P_PARTNER_CLIENT_SECRET ]; then read -p "Give MOSIP OpenG2P Partner Client secret : " MOSIP_OPENG2P_PARTNER_CLIENT_SECRET; fi
if [ -z $MOSIP_OPENG2P_PARTNER_USERNAME ]; then read -p "Give MOSIP OpenG2P Partner Username : " MOSIP_OPENG2P_PARTNER_USERNAME; fi
if [ -z $MOSIP_OPENG2P_PARTNER_PASS ]; then read -p "Give MOSIP OpenG2P Partner Password : " MOSIP_OPENG2P_PARTNER_PASS; fi
if [ -z $MOSIP_OPENG2P_PARTNER_APIKEY ]; then read -p "Give MOSIP OpenG2P Partner ApiKey : " MOSIP_OPENG2P_PARTNER_APIKEY; fi
if [ -z $MOSIP_OPENG2P_PARTNER_MISP_KEY ]; then read -p "Give MOSIP OpenG2P Partner Misp License Key : " MOSIP_OPENG2P_PARTNER_MISP_KEY; fi

if [ -z $OPENG2P_PRIVATE_KEY_PATH ]; then read -p "Give OpenG2P Private Key Path : " OPENG2P_PRIVATE_KEY_PATH; fi
if [ -z $OPENG2P_PUBLIC_CERT_PATH ]; then read -p "Give OpenG2P Public Cert Path : " OPENG2P_PUBLIC_CERT_PATH; fi
if [ -z $MOSIP_IDA_PARTNER_CERT_PATH ]; then read -p "Give MOSIP IDA Partner Cert Path : " MOSIP_IDA_PARTNER_CERT_PATH; fi

# echo Create $NS namespace
# kubectl create ns $NS

# echo Istio Injection Enabled
# kubectl label ns $NS istio-injection=enabled --overwrite

kubectl -n $NS delete --ignore-not-found=true secret openg2p-mosip-partner-creds
kubectl -n $NS create secret generic openg2p-mosip-partner-creds \
  --from-literal=mosip_openg2p_partner_client_id=$MOSIP_OPENG2P_PARTNER_CLIENT_ID \
  --from-literal=mosip_openg2p_partner_client_secret=$MOSIP_OPENG2P_PARTNER_CLIENT_SECRET \
  --from-literal=mosip_openg2p_partner_username=$MOSIP_OPENG2P_PARTNER_USERNAME \
  --from-literal=mosip_openg2p_partner_password=$MOSIP_OPENG2P_PARTNER_PASS \
  --from-literal=mosip_openg2p_partner_apikey=$MOSIP_OPENG2P_PARTNER_APIKEY \
  --from-literal=mosip_openg2p_partner_misp_lk=$MOSIP_OPENG2P_PARTNER_MISP_KEY \

kubectl -n $NS delete --ignore-not-found=true secret openg2p-mosip-partner-certs-keys
kubectl -n $NS create secret generic openg2p-mosip-partner-certs-keys \
  --from-file=openg2p.key=$OPENG2P_PRIVATE_KEY_PATH \
  --from-file=openg2p.crt=$OPENG2P_PUBLIC_CERT_PATH \
  --from-file=ida.partner.crt=$MOSIP_IDA_PARTNER_CERT_PATH

echo Installing openg2p-mosip-auth-mediator...
helm -n $NS install openg2p-mosip-auth-mediator charts/openg2p-mosip-auth-mediator \
  --set mediator.mosip.ida.url=$MOSIP_IDA_URL \
  --set mediator.mosip.ida.domain=$MOSIP_IDA_DOMAIN_URI \
  --set mediator.mosip.iamTokenUrl=$MOSIP_IAM_TOKEN_ENDPOINT \
  --set mediator.openg2p.mosipPartnerClientSecretName="openg2p-mosip-partner-creds" \
  --set mediator.openg2p.certsKeys.secretName="openg2p-mosip-partner-certs-keys" \
  --wait
