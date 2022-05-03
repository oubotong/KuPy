from .model import *

from yaml import load, dump
import os

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

class ConfigParser:
    def __init__(self, filepath=None):
        self.filepath = filepath
        self.containers = []
        self.policies = []

    def parse(self, filepath=None): 
        if filepath == None:
            filepath = self.filepath
        
        if filepath == None:
            print('no filepath specified')
            return

        if os.path.isfile(filepath):
            try:
                with open(filepath) as f:
                    data = load(f, Loader=Loader)
                    #print(data)
                    self.create_object(data)

            except:
                print("Error opening or reading file " + filepath)
            
        else:
            
            try:
                for subdir, dirs, files in os.walk(filepath):
                    for file in files:
                        filename = os.path.join(subdir, file)

                        with open(filename) as f:
                            data = load(f, Loader=Loader)
                            #print(data)
                            self.create_object(data)
            except:
                print("Error opening or reading directory")
                raise 

        return self.containers, self.policies

    def create_object(self, data):
        if data['kind'] == 'NetworkPolicy':
            select = data['spec']['podSelector']['matchLabels']
            if 'Ingress' in data['spec']['policyTypes']:
                for ing in data['spec']['ingress']:
                    allow = None
                    ports = None
                    for f in ing['from']:
                        if 'podSelector' in f:
                            allow = f['podSelector']['matchLabels']
                        if 'ports' in f:
                            ports = [f['ports']['protocol'], f['ports']['port']]
                    new_policy = Policy(data['metadata']['name']+'-ingress', PolicySelect(select), PolicyAllow(allow), PolicyIngress, ports)
                    self.policies.append(new_policy)

            if 'Egress' in data['spec']['policyTypes']:
                for eg in data['spec']['egress']:
                    allow = None
                    ports = None
                    for t in eg['to']:
                        if 'podSelector' in t:
                            allow = t['podSelector']['matchLabels']
                        if 'ports' in t:
                            ports = [t['ports']['protocol'], t['ports']['port']]
                    new_policy = Policy(data['metadata']['name']+'-egress', PolicySelect(select), PolicyAllow(allow), PolicyEgress, ports)
                    self.policies.append(new_policy)

        elif data['kind'] == 'Pod':
            labels = data['metadata']['labels']
            # XXX: use pod name as container name since they are the label owners
            """
            for container in data['spec']['containers']:
                new_container = Container(container['name'], labels)
            """
            new_container = Container(data['metadata']['name'], labels)
            self.containers.append(new_container)


    def print_all(self):
        for c in self.containers:
            print(c)
        for p in self.policies:
            print(p)

def main():
   cp = ConfigParser()
   #cp.parse('/home/h3yin/cs219_network_verification/Kubernetes-verification/kano_py/sample/policy.yaml')
   #cp.parse('/home/h3yin/cs219_network_verification/Kubernetes-verification/kano_py/sample/pod.yaml')
   cp.parse('data')

   cp.print_all()

if __name__ == '__main__':
    main()

