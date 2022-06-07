#!/bin/sh
# Uninstalls opencrvs-mediator
## Usage: ./delete.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

NS=default
while true; do
    read -p "Are you sure you want to delete opencrvs-mediator helm chart?(Y/n) " yn
    if [ $yn = "Y" ]
      then
        helm -n $NS delete openg2p-mosip-auth-mediator
        kubectl -n $NS delete --ignore-not-found=true secret openg2p-mosip-partner-creds
        kubectl -n $NS delete --ignore-not-found=true secret openg2p-mosip-partner-certs-keys
        break
      else
        break
    fi
done
