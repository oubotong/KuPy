# K8s Configuration Verification

## Experiment Setup
* install [minikube](https://minikube.sigs.k8s.io/docs/start/) first
* `python setup.py test`

## K8s Policy Introduction

* [Official doc](https://kubernetes.io/zh/docs/concepts/services-networking/network-policies/)
* [API doc](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/)
* [Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)
* Simplified version:
* - use label/namespace in metadata of every Pods
* - consider `podSelector`, `namespaceSelector`
* - default behavior: deny if declared, allow if not declared
* - deal with `matchExpressions`: set operations

```kubernetes
apiVersion: v1
kind: Pod
metadata:
  name: label-demo
  # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
  # (prefix/)name
  labels:
    environment: production
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
```

```kubernetes
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  # LabelSelector
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    # https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#ipblock-v1-networking-k8s-io
    # cidr + except
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    # https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#labelselectorrequirement-v1-meta
    # matchExpressions (key, operator [in, exists], values)
    # matchLabels: =/==, !=
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    # https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#networkpolicyport-v1-networking-k8s-io
    # port + protocol
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
```

## Kubernetes Policy Specification
* sample spec in [spec.pl](./spec.pl)

## 
