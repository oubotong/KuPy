"""
k8s configuration models
use kubernetes.client.models + adapter
"""
import ipaddress
import z3

from pprint import pprint
from dataclasses import dataclass
from typing import *
from typing_extensions import *
from kubernetes.client.models import (
    V1ObjectMeta,
    V1Pod, 
    V1IPBlock,
    V1LabelSelector,
    V1NetworkPolicy,
    V1NetworkPolicySpec,
    V1NetworkPolicyPeer,
    V1NetworkPolicyPort,
    V1NetworkPolicyEgressRule,
    V1NetworkPolicyIngressRule,
    V1Namespace,
)


class NamespaceAdapter:

    def __init__(self, v1namespace: V1Namespace):
        self._namespace = v1namespace
    
    @property
    def metadata(self) -> V1ObjectMeta:
        # mandatory field
        return self._namespace.metadata

    @property
    def name(self) -> Optional[str]:
        return self.metadata.name
    
    @property
    def namespace(self) -> str:
        if self.metadata.namespace is not None:
            return self.metadata.namespace
        return "default"

    @property
    def labels(self) -> Dict[str, str]:
        return self.metadata.labels if self.metadata.labels else {}

    def to_dict(self):
        return {
            "name": self.name,
            "namespace": self.namespace,
            "labels": self.labels
        }


class PodAdapter:
    """
    provide some adapter function for k8s client models
    potentially, we can parse it from kubectl outputs
    """

    def __init__(self, v1pod: V1Pod):
        self.pod = v1pod

    @property
    def metadata(self) -> V1ObjectMeta:
        # mandatory field
        return self.pod.metadata

    @property
    def name(self) -> Optional[str]:
        return self.metadata.name
    
    @property
    def namespace(self) -> str:
        if self.metadata.namespace is not None:
            return self.metadata.namespace
        return "default"

    @property
    def labels(self) -> Dict[str, str]:
        return self.metadata.labels if self.metadata.labels else {}

    def to_dict(self):
        return {
            "name": self.name,
            "namespace": self.namespace,
            "labels": self.labels
        }


@dataclass
class ExistRelation:
    EXISTS: ClassVar[int] = 2
    DOES_NOT_EXISTS: ClassVar[int] = 3

    operator: int
    key: str

    def to_dict(self):
        return {
            "operator": self.operator,
            "key": self.key
        }


@dataclass
class InRelation:
    IN: ClassVar[int] = 0
    NOT_IN: ClassVar[int] = 1

    operator: int
    key: str
    values: List[str]

    def to_dict(self):
        return {
            "operator": self.operator,
            "key": self.key,
            "values": self.values
        }


class LabelSelectorAdapter:
    """
    A label selector is a label query over a set of resources. 
    The result of matchLabels and matchExpressions are ANDed. 
    An empty label selector matches all objects. 
    A null label selector matches no objects.
    """

    def __init__(self, selector: V1LabelSelector):
        self.selector = selector

    @property
    def match_expressions(self) -> Optional[List[Union[ExistRelation, InRelation]]]:
        """
        matchExpressions is a list of label selector requirements. The requirements are ANDed
        inequality matchLabels should be rewritten to matchExpressions (env != ...)
        """
        # NOTE: can't convert to []! different semantics
        if self.selector.match_expressions is None:
            return None
        exprs = []
        for expr in self.selector.match_expressions:
            if expr.operator.lower() == "in":
                exprs.append(InRelation(InRelation.IN, expr.key, expr.values))
            if expr.operator.lower() == "notin":
                exprs.append(InRelation(InRelation.NOT_IN, expr.key, expr.values))
            if expr.operator.lower() == "exists":
                exprs.append(ExistRelation(ExistRelation.EXISTS, expr.key))
            if expr.operator.lower() == "doesnotexists":
                exprs.append(ExistRelation(ExistRelation.DOES_NOT_EXISTS, expr.key))        
        return exprs

    @property
    def match_labels(self) -> Optional[Dict[str, str]]:
        """
        matchLabels is a map of {key,value} pairs. 
        A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, 
            whose key field is "key", the operator is "In", and the values array contains only "value". 
        The requirements are ANDed.
        """
        # NOTE: can't convert to {}! different semantics
        # {}: no label allowed
        # None: no matchLabels rule, allow all
        return self.selector.match_labels

    def to_dict(self):
        return {
            "match_labels": self.match_labels,
            "match_expressions": self.selector.match_expressions if self.selector.match_expressions else None
        }

    def define_label_selector(self, idx: int, gi, var, rhs: List[Any], prefix: str, is_namespace=False) -> bool:
        """
        Return a boolean value indicating quick fail -> no possible key
        An empty label selector matches all objects. (matchExpressions == matchLabels == null)
        A null label selector matchs no objects (e.g. if namespace_selectors == null)
        """
        match_expr = self.match_expressions
        match_label = self.match_labels

        if match_expr is not None:
            for expr in match_expr:
                key_label = None
                key_label_exists = None
                if is_namespace:
                    key_label = "{}__namespace".format(expr.key)
                    key_label_exists = "{}__exists".format(key_label)
                    key_label = gi.get_relation_ns(key_label)
                    key_label_exists = gi.get_relation_ns(key_label_exists)
                else:
                    key_label = expr.key
                    key_label_exists = "{}__exists".format(key_label)
                    key_label = gi.get_relation(key_label)
                    key_label_exists = gi.get_relation(key_label_exists)
                # quick fail, no possible match
                if key_label is None or key_label_exists is None:
                    return True

                if expr.operator == ExistRelation.EXISTS:
                    rhs.append(key_label_exists(var))
                elif expr.operator == ExistRelation.DOES_NOT_EXISTS:
                    rhs.append(z3.Not(key_label_exists(var)))
                else:
                    values = expr.values
                    in_func_name = "{}_{}_{}_in_{}".format(prefix, idx, expr.key, "namespace" if is_namespace else "pod")
                    in_func = z3.Function(in_func_name, gi.pod_sort, z3.BoolSort())
                    in_var = None
                    if is_namespace:
                        in_var = gi.declare_var("in_nam_var", gi.nam_sort)
                    else:
                        in_var = gi.declare_var("in_pod_var", gi.pod_sort)
                    gi.register_relation(in_func_name, in_func, is_core=True)

                    for v in values:
                        gi.add_rule(in_func(in_var), key_label(in_var, gi.get_or_create_literal(v)))
                    
                    if expr.operator == InRelation.IN:
                        rhs.append(in_func(var))
                    else:
                        rhs.append(z3.Not(in_func(var)))

        if match_label is not None:
            for k, v in match_label.items():
                k_entity = k
                if is_namespace:
                    k_entity = k_entity + "__namespace"
                    k_entity = gi.get_relation_ns(k_entity)
                else:
                    k_entity = gi.get_relation(k_entity)

                # quick fail
                if k_entity is None:
                    return True

                rhs.append(k_entity(var, gi.get_or_create_literal(v)))

        return False


IPAddress = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
class PolicyPeerAdapter:

    def __init__(self, peer: V1NetworkPolicyPeer, direction):
        self.peer = peer
        self.direction = direction

    @property
    def ip_block(self) -> Optional[Tuple[IPAddress, List[IPAddress]]]:
        """
        TODO: for current version, may ignore this selector
        IPBlock defines policy on a particular IPBlock. 
        If this field is set then neither of the other fields can be.
        """
        # CIDR is a string representing the IP Block Valid examples are "192.168.1.1/24" or "2001:db9::/64"
        if self.peer.ip_block is None:
            return None

        ip_block: V1IPBlock = self.peer.ip_block
        cidr = ipaddress.ip_network(ip_block.cidr)
        
        if ip_block._except is None:
            return (cidr, [])
        return (cidr, list(map(ipaddress.ip_network, ip_block._except)))

    @property
    def namespace_selector(self) -> Optional[LabelSelectorAdapter]:
        """
        Selects Namespaces using cluster-scoped labels. 
        This field follows standard label selector semantics; 
            if present but empty, it selects all namespaces. 
        If PodSelector is also set, then the NetworkPolicyPeer as a whole selects the Pods matching PodSelector in the Namespaces selected by NamespaceSelector. 
        Otherwise it selects all Pods in the Namespaces selected by NamespaceSelector.
        """
        if self.peer.namespace_selector is None:
            return None
        return LabelSelectorAdapter(self.peer.namespace_selector)

    @property
    def pod_selector(self) -> Optional[LabelSelectorAdapter]:
        """
        This is a label selector which selects Pods. 
        This field follows standard label selector semantics; 
            if present but empty, it selects all pods. 
        If NamespaceSelector is also set, then the NetworkPolicyPeer as a whole selects the Pods matching PodSelector in the Namespaces selected by NamespaceSelector. 
        Otherwise it selects the Pods matching PodSelector in the policy's own Namespace.
        """
        if self.peer.pod_selector is None:
            return None
        return LabelSelectorAdapter(self.peer.pod_selector)

    def to_dict(self):
        return {
            "pod_selector": self.pod_selector.to_dict() if self.pod_selector else None,
            "namespace_selector": self.namespace_selector.to_dict() if self.namespace_selector else None,
            "ip_block": self.ip_block
        }

    def define_peer_selector(self, idx: int, gi, pod_var, ns_var, rhs: List[Any], is_namespace=False) -> bool:
        if self.namespace_selector is not None:
            fail = self.namespace_selector.define_label_selector(idx, gi, ns_var, rhs, self.direction, is_namespace=True)
            # quick fail
            if fail:
                return True
        if self.pod_selector is not None:
            fail = self.pod_selector.define_label_selector(idx, gi, pod_var, rhs, self.direction)
            # quick fail
            if fail:
                return True
        return False


class PolicyRuleAdatper:
    """
    provide some adapter function for k8s policy rules
    """
    INGRESS = 0
    EGRESS = 1

    def __init__(self, rule: Union[V1NetworkPolicyEgressRule, V1NetworkPolicyIngressRule]):
        if type(rule) == V1NetworkPolicyEgressRule:
            self.direction = PolicyRuleAdatper.EGRESS
        else:
            self.direction = PolicyRuleAdatper.INGRESS
        self.rule = rule

    @property
    def peer(self) -> Optional[List[PolicyPeerAdapter]]:
        """
        ingress: [] -> deny all
        ingress: - {} -> allow all
        List of destinations for outgoing traffic of pods selected for this rule. 
        Items in this list are combined using a logical OR operation. 
        If this field is empty or missing, this rule matches all destinations (traffic not restricted by destination). 
        If this field is present and contains at least one item, this rule allows traffic only if the traffic matches at least one item in the to list.
        """
        if self.direction == PolicyRuleAdatper.EGRESS:
            if self.rule.to is None:
                return None
            return list(map(lambda x: PolicyPeerAdapter(x, "egress_allow"), self.rule.to))
        if self.rule._from is None:
            return None
        return list(map(lambda x: PolicyPeerAdapter(x, "ingress_allow"), self.rule._from))

    def define_peer_rule(self, idx: int, gi, pod_var, ns_var) -> List[List[Any]]:
        # return many OR branches

        # If this field is empty or missing, this rule matches all destinations -> no rhs added
        if self.peer is None:
            return

        all_rhs = []
        for p in self.peer:
            rhs = []
            fail = p.define_peer_selector(idx, gi, pod_var, ns_var, rhs)
            if not fail:
               all_rhs.append(rhs)
        return all_rhs

    @property
    def ports(self) -> Optional[List[Tuple[Optional[Union[int, str]], str]]]:
        """
        List of destination ports for outgoing traffic. 
        Each item in this list is combined using a logical OR. 
        If this field is empty or missing, this rule matches all ports (traffic not restricted by port). 
        If this field is present and contains at least one item, then this rule allows traffic only if the traffic matches at least one port in the list.
        """
        if self.rule.ports is None:
            return None

        ports: List[V1NetworkPolicyPort] = self.rule.ports
        results = []

        for p in ports:
            # port could be numerical or named port on a pod
            # If this field is not provided, this matches all port names and numbers
            if p.protocol is not None:
                results.append((p.port, p.protocol))
            else:
                results.append((p.port, "TCP"))

    def to_dict(self):
        return {
            "peers": list(map(PolicyPeerAdapter.to_dict, self.peer)) if self.peer else None,
            "ports": self.ports
        }


class PolicyAdapter:
    """
    provide some adapter function for k8s policy models
    """
    INGRESS = 0
    EGRESS = 1

    def __init__(self, v1policy: V1NetworkPolicy):
        self.policy = v1policy

    @property
    def metadata(self) -> V1ObjectMeta:
        # mandatory field
        return self.policy.metadata

    @property
    def namespace(self) -> str:
        if self.metadata.namespace is not None:
            return self.metadata.namespace
        return "default"

    @property
    def spec(self) -> Optional[V1NetworkPolicySpec]:
        return self.policy.spec

    @property
    def egress_rules(self) -> Optional[List[PolicyRuleAdatper]]:
        """
        List of egress rules to be applied to the selected pods. 
        Outgoing traffic is allowed if 
            there are no NetworkPolicies selecting the pod (and cluster policy otherwise allows the traffic), 
            OR if the traffic matches at least one egress rule across all of the NetworkPolicy objects whose podSelector matches the pod
        If this field is empty then this NetworkPolicy limits all outgoing traffic (and serves solely to ensure that the pods it selects are isolated by default)
        """
        if self.spec.egress is None:
            return None
        return list(map(PolicyRuleAdatper, self.spec.egress))

    def define_egress_rules(self, idx: int, gi):
        egress_allow_by_pol = gi.get_relation_core("egress_allow_by_pol")
        namespace = gi.get_relation_core("namespace")
        pod_var = gi.declare_var('pod', gi.pod_sort)
        ns_var = gi.declare_var('ns', gi.nam_sort)

        # if egress is empty, this NetworkPolicy limits all outgoing traffic
        # no egress_allow_by_pol(Pod, idx) defined
        if self.egress_rules is None:
            return

        # each egress rule is independent (OR-chained)
        for egress in self.egress_rules:
            rhses = egress.define_peer_rule(idx, gi, pod_var, ns_var)
            # each peer in each rule is OR-chained
            for rhs in rhses:
                rhs.insert(0, namespace(pod_var, ns_var))
                gi.add_rule(egress_allow_by_pol(pod_var, gi.pol_value(idx)), rhs)

    @property
    def ingress_rules(self) -> Optional[List[PolicyRuleAdatper]]:
        """
        List of ingress rules to be applied to the selected pods. 
        Traffic is allowed if 
            there are no NetworkPolicies selecting the pod (and cluster policy otherwise allows the traffic), 
            OR if the traffic source is the pod's local node, 
            OR if the traffic matches at least one ingress rule across all of the NetworkPolicy objects whose podSelector matches the pod
        If this field is empty then this NetworkPolicy does not allow any traffic (and serves solely to ensure that the pods it selects are isolated by default)        
        """
        # ingress: []
        if self.spec.ingress is None:
            return None
        return list(map(PolicyRuleAdatper, self.spec.ingress))

    def define_ingress_rules(self, idx: int, gi):
        ingress_allow_by_pol = gi.get_relation_core("ingress_allow_by_pol")
        namespace = gi.get_relation_core("namespace")
        pod_var = gi.declare_var('pod', gi.pod_sort)
        ns_var = gi.declare_var('ns', gi.nam_sort)

        # if ingress is empty, this NetworkPolicy does not allow any traffic
        # no ingress_allow_by_pol(Pod, idx) defined
        if self.ingress_rules is None:
            return

        # each ingress rule is independent (OR-chained)
        for ingress in self.ingress_rules:
            rhses = ingress.define_peer_rule(idx, gi, pod_var, ns_var)
            # each peer in each rule is OR-chained
            for rhs in rhses:
                rhs.insert(0, namespace(pod_var, ns_var))
                gi.add_rule(ingress_allow_by_pol(pod_var, gi.pol_value(idx)), rhs)

    @property
    def pod_selector(self) -> Optional[LabelSelectorAdapter]:
        """
        Selects the pods to which this NetworkPolicy object applies. 
        The array of ingress rules is applied to any pods selected by this field.
        Multiple network policies can select the same set of pods. In this case, the ingress rules for each are combined additively. 
        This field is NOT optional and follows standard label selector semantics. 
        An empty podSelector matches all pods in this namespace.
        Q: Work with namespace in metadata?
        """
        if self.spec.pod_selector is None:
            return None
        return LabelSelectorAdapter(self.spec.pod_selector)

    def define_pod_selector(self, idx: int, gi):
        selected_by_pol = gi.get_relation_core("selected_by_pol")
        namespace = gi.get_relation_core("namespace")
        pod_var = gi.declare_var('pod', gi.pod_sort)
        
        # quick fail -> no possible namespace, omit this rule
        if self.namespace not in gi.nam_map:
            return
        
        rhs = []
        rhs.append(namespace(pod_var, gi.get_namespace_idx(self.namespace)))

        # An empty podSelector matches all pods in this namespace.
        if self.pod_selector is None:
            pass
        else:
            fail = self.pod_selector.define_label_selector(idx, gi, pod_var, rhs, "select_by_pol")
            # quick fail, no possible selection
            if fail:
                return

        gi.add_rule(selected_by_pol(pod_var, gi.pol_value(idx)), rhs)

    @property
    def policy_types(self) -> List[int]:
        """
        List of rule types that the NetworkPolicy relates to. 
        Valid options are "Ingress", "Egress", or "Ingress,Egress"
        """
        if self.spec is None:
            return []

        tys = []
        if self.spec.policy_types is not None:
            tystrs = list(map(str.lower, self.spec.policy_types))
            if 'ingress' in tystrs:
                tys.append(PolicyAdapter.INGRESS)                        
            if 'egress' in tystrs:
                tys.append(PolicyAdapter.EGRESS)
            return tys

        if self.spec.ingress is not None:
            tys.append(PolicyAdapter.INGRESS)
        if self.spec.egress is not None:
            tys.append(PolicyAdapter.EGRESS)

        return tys

    def to_dict(self):
        return {
            "namespace": self.namespace,
            "egress_rules": list(map(PolicyRuleAdatper.to_dict, self.egress_rules)) if self.egress_rules else None,
            "ingress_rules": list(map(PolicyRuleAdatper.to_dict, self.ingress_rules)) if self.ingress_rules else None,
            "pod_selector": self.pod_selector.to_dict() if self.pod_selector else None,
            "policy_types": self.policy_types
        }
