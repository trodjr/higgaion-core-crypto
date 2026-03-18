------------------------------ MODULE Gateway ------------------------------
EXTENDS Naturals, Sequences

CONSTANTS
  Tokens,       \* Set of all possible JWT tokens
  AdminTokens,  \* Subset of Tokens with ROLE_KEY_ADMIN or ROLE_AUDITOR
  Endpoints     \* Set of API endpoints

VARIABLES
  in_flight,    \* Requests currently being processed by the Gateway
  c_node_hits,  \* Requests that have successfully reached the C Node proxy
  audit_logs    \* Sequence of generated SIEM logs

vars == <<in_flight, c_node_hits, audit_logs>>

-----------------------------------------------------------------------------
\* Request Structure
Requests == [token: Tokens, endpoint: Endpoints]

\* Initial State
Init ==
  /\ in_flight = {}
  /\ c_node_hits = {}
  /\ audit_logs = {}

\* Transition 1: A client sends a new request to the Gateway
ReceiveRequest(r) ==
  /\ r \notin in_flight
  /\ in_flight' = in_flight \cup {r}
  /\ UNCHANGED <<c_node_hits, audit_logs>>

\* Transition 2: Gateway processes an unauthorized request (drops it)
DropUnauthorized(r) ==
  /\ r \in in_flight
  /\ r.token \notin AdminTokens
  /\ in_flight' = in_flight \ {r}
  /\ audit_logs' = audit_logs \cup {[type |-> "API_ACCESS", req |-> r]}
  /\ UNCHANGED c_node_hits

\* Transition 3: Gateway processes an authorized request (proxies to C Node)
ProxyAuthorized(r) ==
  /\ r \in in_flight
  /\ r.token \in AdminTokens
  /\ in_flight' = in_flight \ {r}
  /\ c_node_hits' = c_node_hits \cup {r}
  /\ audit_logs' = audit_logs \cup {[type |-> "API_ACCESS", req |-> r]}

\* Combined Next State Relation
Next ==
  \/ \E r \in Requests : ReceiveRequest(r)
  \/ \E r \in in_flight : DropUnauthorized(r)
  \/ \E r \in in_flight : ProxyAuthorized(r)

-----------------------------------------------------------------------------
\* INVARIANTS TO PROVE

\* 1. Strict Isolation: Only Admin/Auditor tokens ever reach the C Node
StrictIsolation ==
  \A r \in c_node_hits : r.token \in AdminTokens

\* 2. Audit Irrefutability: Every request that reaches the C Node must have exactly one corresponding API_ACCESS SIEM log
AuditIrrefutability ==
  \A r \in c_node_hits :
    \E log \in audit_logs :
      /\ log.type = "API_ACCESS"
      /\ log.req = r

\* Safety encompasses both invariants
Safety ==
  /\ StrictIsolation
  /\ AuditIrrefutability

=============================================================================
