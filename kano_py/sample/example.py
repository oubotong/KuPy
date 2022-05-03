from kano.model import *


def paper_example():
    containers = [
        Container("A", {
            "app": "Alice",
            "role": "Nginx"
        }),
        Container("B", {
            "app": "Alice",
            "role": "DB"
        }),
        Container("C", {
            "app": "Alice",
            "role": "Tomcat"
        }),
        Container("D", {
            "app": "Bob",
            "role": "Nginx"
        }),
        Container("E", {
            "app": "User",
            "role": "User"
        }),
    ]

    # simple example: Nginx -> DB, User -> Tomcat, Tomcat -> Nginx
    policies = [
        Policy(
            "A",
            PolicySelect({"role": "DB"}),
            PolicyAllow({"role": "Nginx"}),
            PolicyIngress,
            PolicyProtocol(["TCP", "3306"])
        ),
        Policy(
            "B",
            PolicySelect({"role": "Tomcat"}),
            PolicyAllow({"role": "User"}),
            PolicyIngress,
            PolicyProtocol(["TCP", "8080"])
        ),
        Policy(
            "C",
            PolicySelect({"role": "Nginx"}),
            PolicyAllow({"role": "Tomcat"}),
            PolicyIngress,
            PolicyProtocol(["TCP", "3306"])
        ),
        Policy(
            "D",
            PolicySelect({"role": "Nginx"}),
            PolicyAllow({"app": "Alice"}),
            PolicyIngress,
            PolicyProtocol(["TCP", "3306"])
        ),
    ]

    return containers, policies
