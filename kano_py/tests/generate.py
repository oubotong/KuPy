import os
import random
import yaml
from collections import OrderedDict
from ..kano.model import *

class ConfigFiles:
    def __init__(self, directory='data', podN=100,nsN=5,policyN=50,podLL=5,nsLL=5,keyL=5,valueL=10,userL=5,selectedLL=3,allowNSLL=3,allowpodLL=3):
        self.podN = podN
        self.nsN = nsN
        self.policyN = policyN
        self.podLL = podLL
        self.nsLL = nsLL
        self.keys = ["key"+str(i) for i in range(keyL)]
        self.values = ["value"+str(i) for i in range(valueL)]
        self.userL = userL
        self.users = ["user"+str(i) for i in range(userL)]
        self.selectedLL = selectedLL
        self.allowNSLL = allowNSLL
        self.allowpodLL = allowpodLL
        self.directory = directory
        if not os.path.exists(directory):
            os.makedirs(directory)
        self.generatePods()
        # self.generateNamespaces()

    def generatePods(self):
        containers = []
        for i in range(self.podN):
            podName = "pod" + str(i)
            # nsName = random.choice(namespaces)
            labels = {}
            labels["User"] = random.choice(self.users)
            for l in range(random.randint(0, self.podLL-1)):
                labels[random.choice(self.keys)] = random.choice(self.values)
            pod = Container(podName, labels)
            containers.append(pod)

            y_pod = {}
            y_pod['apiVersion'] = 'v1'
            y_pod['kind'] = 'Pod'
            y_pod['metadata'] = {
                'name': podName,
                'namespace': 'default',
                'labels': labels
            }
            with open("{}/pod{}.yml".format(self.directory, i), 'w+') as f:
                f.write(yaml.dump(y_pod, default_flow_style=False, sort_keys=False))

        self.containers = containers
        return


    # def generateNamespaces(self):
    #     namespaces = []
    #     for i in range(self.nsN):
    #         nsName = "namespace" + str(i)
    #         labels = {}
    #         for l in range(random.randint(0, self.nsLL-1)):
    #             labels[random.choice(self.keys)] = random.choice(self.values)
    #         ns = Namespace(nsName, labels)
    #         namespaces.append(ns)
    #     self.namespaces = namespaces
    #     return


    def generateConfigFiles(self):
        for i in range(self.policyN):
            # format
            data = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test-network-policy\n  namespace: default\n"
            data += "spec:\n  podSelector:\n    matchLabels:\n"
            # randomly select two containers
            candidates = random.sample(self.containers, 2)
            data += self.printLabels(candidates[0], "      ")
            # format
            #data += "  policyTypes:\n  - Ingress\n  - Egress\n"
            #data += random.choice(["  ingress", "  egress"])
            #data += ":\n  - from:\n    - podSelector:\n        matchLabels:\n"

            data += "  policyTypes:\n"
            choice = random.choice(["  ingress", "  egress"])
            if choice == "  ingress":
                data += "  - Ingress\n" + choice + ":\n  - from:\n"
            elif choice == "  egress":
                data += "  - Egress\n" + choice + ":\n  - to:\n"
            data +="    - podSelector:\n        matchLabels:\n"

            data += self.printLabels(candidates[1], "          ")

            # write to config file
            #f = open(self.directory + str(i) + ".yml", "a")
            f = open(self.directory + "/policy" + str(i) + ".yml", "w")
            f.write(data)
            f.close()
        return

    def printLabels(self, container, indent):
        string = str(indent) + "User: " + str(container.getValueOrDefault("User", "")) + "\n"
        count = 0
        for key,value in container.getLabels().items():
            if count>=3:
                break
            if key == "User":
                continue
            string += str(indent) + str(key) + ": " + str(value) + "\n"
            count += 1
        return string

    def getPods(self):
        return self.containers


if __name__ == "__main__":
    config = ConfigFiles()
    config.generateConfigFiles()
