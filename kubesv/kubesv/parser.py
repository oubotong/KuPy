"""
k8s yaml file -> model
XXX: could just generate models instead
"""
import yaml
from kubernetes import client, config


def from_dict(kind: str, data: dict):
    config.load_kube_config()
    api = client.ApiClient()
    
    class FakeResposne:
        def __init__(self, obj):
            import json
            self.data = json.dumps(obj)

    return api.deserialize(FakeResposne(data), kind)


def from_yaml(kind: str, yml: str):
    return from_dict(kind, yaml.safe_load(yml))        
