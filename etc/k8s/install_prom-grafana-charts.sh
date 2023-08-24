#!/bin/bash

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

helm repo update

cd ./prom-grafana-charts/charts

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -f ./default-kube-prom-custom-value.yaml --version 42.2.0
