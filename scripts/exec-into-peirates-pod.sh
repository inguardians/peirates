#!/usr/bin/env bash

# Email: peirates-dev <peirates-dev@inguardians.com>

NAMESPACE="totally-innocuous" # this is an EXAMPLE namespace

function usage() {
  echo "Pod connect script."
  echo
  echo "Syntax: ${0} [-h|-n]"
  echo "options:"
  echo "-h     Print this Help."
  echo "-n     Specify a Namespace."
}

function main() {
  # echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  # kubectl rollout status deployment/peirates -n ${NAMESPACE}
  # echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  # kubectl get deployments -n ${NAMESPACE}
  # echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  # kubectl get pods -n ${NAMESPACE}
  
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  # identify pod by label and show details
  MY_POD2=$(kubectl get pods --selector=app=totally-not-peirates -n ${NAMESPACE} | grep -v ^NAME | cut -f1 -d' ')
  [ -z "$var" ] || exit 1
  echo "My pod: ${MY_POD2}"
  
  # saving these just in case, can delete soon if not needed.
  # identify pod by name/namespace and show details
  #   MY_POD=$(kubectl describe pods -n ${NAMESPACE} ) # what happens if there are multiple pods?
  #   # MY_POD=$(kubectl describe pods -n ${NAMESPACE} | grep ^Name: | rev | cut -f1 -d' '| rev)
  #   [ -z "$var" ] || exit 1
  #   echo "My pod: ${MY_POD}"
  
  echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
  kubectl exec -it $(kubectl describe pods -n ${NAMESPACE} | grep ^Name: | rev | cut -f1 -d' '| rev) -n ${NAMESPACE} -- /peirates
}

while getopts "h:n:" option; do
  case $option in
    h)
      usage
      exit 0
    ;;
    n)
      NAMESPACE=${OPTARG}
      main
      exit 0
    ;;
    \?)
      usage
      exit 1
    ;;
  esac
done

if [ "$option" = "?" ]; then
  usage && exit 1
fi