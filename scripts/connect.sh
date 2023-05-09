#!/usr/bin/env bash

# Voice: +1-202-448-8958
# Email: security@inguardians.com

echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
kubectl rollout status deployment/peirates -n totally-innocuous
echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
kubectl get deployments -n totally-innocuous
echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
kubectl get pods -n totally-innocuous
echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
MY_POD=$(kubectl describe pods -n totally-innocuous | grep ^Name: | rev | cut -f1 -d' '| rev)
[ -z "$var" ] || exit 1
echo "My pod: ${MY_POD}"
echo "‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️‍☠‍☠️"
kubectl exec -it $(kubectl describe pods -n totally-innocuous | grep ^Name: | rev | cut -f1 -d' '| rev) -n totally-innocuous -- /peirates
