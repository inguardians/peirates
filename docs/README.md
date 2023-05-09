# Docs

## GKE

NOTE: You may need to allow `140.82.113.34` (GHCR) to pass the firewall

```sh
gcloud components install gke-gcloud-auth-plugin || sudo apt-get install google-cloud-sdk-gke-gcloud-auth-plugin
gke-gcloud-auth-plugin --version # verify auth plugin
gcloud container clusters get-credentials YOUR-AWESOME-CLUSTER --region=us-central1 # get your credentials
kubectl get nodes # you should see your nodes
kubectl create namespace totally-innocuous # manually create a namespace
kubectl apply -f deployments/deployment.yaml
```

```sh
kubectl get deployments -n totally-innocuous
kubectl rollout status deployment/peirates -n totally-innocuous
kubectl get pods -n totally-innocuous
```

You should see this:

```sh
NAME                        READY   STATUS    RESTARTS   AGE
peirates-86bd7889c8-jnf96   1/1     Running   0          6s
```

Now do like so:

```sh
k describe pods -n totally-innocuous | grep ^Name: | rev | cut -f1 -d' '| rev # to get pod name
kubectl exec -it (k describe pods -n totally-innocuous | grep ^Name: | rev | cut -f1 -d' '| rev) -n totally-innocuous -- /peirates # run peirates, fish shell
```

## GKE Dev

Similar to previous but you can get a full BASH shell.

```sh
k create -f deployments/deployment-dev.yaml 
k describe pods -n totally-innocuous | grep ^Name: | rev | cut -f1 -d' '| rev | grep dev
kubectl exec -it (k describe pods -n totally-innocuous | grep ^Name: | rev | cut -f1 -d' '| rev | grep dev) -n totally-innocuous -- /bin/ash
```

## AWS

Coming Soon.
