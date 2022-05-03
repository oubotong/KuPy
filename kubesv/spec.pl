% TODO: cluster policies, ip blocks, ports

% namespace fact
namespace(Pod, value).

% pod_selector
select_by_pol(Pod, Pol) :-
    namespace(Pod, PolNameSpace),
    % if matchLabels
    label(Pod, LabelValue),
    % if matchExpressions.Exists
    label_exists(Pod),
    % if matchExpressions.In
    selected_by_pol_idx_label_in(Pod),
    % if matchExpressions.DoesNotExists
    \(label_exists(Pod)),
    % if matchExpressions.NotIn
    \(selected_by_pol_idx_label_in(Pod))
    .
select_by_pol_idx_label_in(Pod) :- label(Pod, LabelValue0).
select_by_pol_idx_label_in(Pod) :- label(Pod, LabelValue1).
select_by_pol_idx_label_in(Pod) :- label(Pod, LabelValue2).

% policy ingress part
% -------------------

ingress_allow_by_pol(Pod, Pol) :-
    % if namespaceSelector
    namespace(Pod, PodNamespace),
    % if namespaceSelector.matchLabels
    label_namespace(PodNamespace, LabelValue),
    % if namespaceSelector.matchExpressions.Exists
    label_namespace_exists(PodNamespace),
    % if namespaceSelector.matchExpressions.In
    selected_by_pol_idx_label_namespace_in(PodNamespace),
    % if namespaceSelector.matchExpressions.DoesNotExists
    \(label_namespace_exists(PodNamespace)),
    % if namespaceSelector.matchExpressions.NotIn
    \(selected_by_pol_idx_label_namespace_in(PodNamespace)),
    % if podSelector.matchLabels
    label(Pod, LabelValue),
    % if podSelector.matchExpressions.Exists
    label_exists(Pod),
    % if podSelector.matchExpressions.In
    ingress_by_pol_idx_label_in(Pod),
    % if podSelector.matchExpressions.DoesNotExists
    \(label_exists(Pod)),
    % if podSelector.matchExpressions.NotIn
    \(ingress_by_pol_idx_label_in(Pod)),
    .

% multiple entry in ingress.from
ingress_allow_by_pol(Pod, Pol) :-
    % empty if ingress.from is empty/missing -> matching all
    .

% policy egress part
% -------------------

% similar to ingress part

% reachability part
% -------------------

select_by_any(Pod) :-
    is_pol(Pol),
    select_by_pol(Pod, Pol)
    .

% if the traffic source is the pod's local node
ingress_traffic(Pod, Pod).

% ... OR if the traffic matches at least one ingress rule across all of the NetworkPolicy objects whose podSelector matches the pod
ingress_traffic(SrcPod, SelectedPod) :-
    select_by_pol(SelectedPod, Pol),
    ingress_allow_by_pol(SrcPod, Pol)
    .

% ... OR there are no NetworkPolicies selecting the pod (and cluster policy otherwise [like ClusterRole] allows the traffic)
ingress_traffic(_, SelectedPod) :-
    \(select_by_any(SelectedPod)).

% if the traffic matches at least one ingress rule across all of the NetworkPolicy objects whose podSelector matches the pod
egress_traffic(DstPod, SelectedPod) :-
    select_by_pol(SelectedPod, Pol),
    egress_allow_by_pol(SrcPod, Pol)
    .

% ... OR there are no NetworkPolicies selecting the pod (and cluster policy otherwise [like ClusterRole] allows the traffic)
egress_traffic(_, SelectedPod) :-
    \(select_by_any(SelectedPod)).

edge(SrcPod, DstPod) :-
    ingress_traffic(SrcPod, X),
    egress_traffic(DstPod, X).