from pprint import pprint
from kubesv.parser import from_yaml
from kubesv.model import PodAdapter, NamespaceAdapter, PolicyAdapter


def config_example():
    policy = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: myproject
        matchExpressions:
          - {key: environment, operator: In, values: [dev]}
          - {key: tier, operator: Exists}
    - podSelector:
        matchLabels:
          role: frontend
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
"""

    allow_all_egress = """
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  ingress: []
"""
    nginx = """
apiVersion: v1
kind: Pod
metadata:
  name: label-demo
  labels:
    environment: production
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
"""

    policy = PolicyAdapter(from_yaml('V1NetworkPolicy', policy))
    nginx = PodAdapter(from_yaml('V1Pod', nginx))
    return nginx, policy


def ns_template(name, labels):
    ns_templ = """
kind: Namespace
apiVersion: v1
metadata:
  name: {}
  namespace: {}
"""
    ns = from_yaml('V1Namespace', ns_templ.format(name, name))
    ns.metadata.labels = labels
    return NamespaceAdapter(ns)


def pod_template(name, namespace, labels):
    pod_templ = """
apiVersion: v1
kind: Pod
metadata:
  name: {}
  namespace: {}
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
"""
    pod = from_yaml('V1Pod', pod_templ.format(name, namespace))
    pod.metadata.labels = labels
    return PodAdapter(pod)


def paper_example():
    nams = [
        ns_template("default", {"nonsense": "default"}), 
        ns_template("minikube", {"nonsense": "emmm", "l": "minikube"})
    ]

    pods = []

    from itertools import product
    for idx, p in enumerate(product(
            ['db', 'nginx', 'tomcat'],
            ['default', 'minikube'],
            ['prod', 'test'])):
        role, ns, env = p
        name = "{}_{}".format(role, idx)
        pods.append(pod_template(name, ns, {
            "env": env,
            "role": role
        }))

    def sample_policy0():
        yml = """
apiVersion: v1
kind: NetworkPolicy
metadata:
  name: allow-default-nginx
  namespace: default
spec:
  podSelector:
    matchExpressions:
        - {key: role, operator: NotIn, values: [tomcat, nginx]}
    matchLabels:
        env: prod
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          nonsense: default
      podSelector:
        matchLabels:
          role: tomcat
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - podSelector:
        matchExpressions:
          - {key: role, operator: NotIn, values: [db, nginx]}
      namespaceSelector:
        matchExpressions:
          - {key: l, operator: DoesNotExists}
    ports:
    - protocol: TCP
      port: 5978
"""
        return PolicyAdapter(from_yaml('V1NetworkPolicy', yml))

    def sample_policy1():
        yml = """
apiVersion: v1
kind: NetworkPolicy
metadata:
  name: allow-default-nginx
  namespace: default
spec:
  podSelector:
    matchExpressions:
        - {key: role, operator: NotIn, values: [tomcat, nginx]}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          nonsense: default
      podSelector:
        matchLabels:
          role: tomcat
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - podSelector:
        matchExpressions:
          - {key: role, operator: NotIn, values: [db, nginx]}
      namespaceSelector:
        matchExpressions:
          - {key: l, operator: DoesNotExists}
    ports:
    - protocol: TCP
      port: 5978
"""
        return PolicyAdapter(from_yaml('V1NetworkPolicy', yml))

    def sample_policy2():
        yml = """
apiVersion: v1
kind: NetworkPolicy
metadata:
  name: allow-default-nginx
  namespace: default
spec:
  podSelector:
    matchExpressions:
        - {key: role, operator: NotIn, values: [db, nginx]}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          nonsense: default
      podSelector:
        matchLabels:
          role: db
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - podSelector:
        matchExpressions:
          - {key: role, operator: NotIn, values: [tomcat, nginx]}
      namespaceSelector:
        matchExpressions:
          - {key: l, operator: DoesNotExists}
    ports:
    - protocol: TCP
      port: 5978
"""
        return PolicyAdapter(from_yaml('V1NetworkPolicy', yml))

    # pprint(sample_policy().to_dict())

    pols = [
        sample_policy0(),
        sample_policy1(),
        sample_policy2()
    ]
    
    return pods, pols, nams    
