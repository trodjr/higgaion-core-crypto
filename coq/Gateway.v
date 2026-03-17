(* =========================================================================
   Gateway.v — Enterprise Gateway Proxy State Machine Invariants

   Mechanized proofs for the Enterprise Gateway sidecar.
   Proves: Strict Isolation and Audit Irrefutability invariants.
   ========================================================================= *)

From Coq Require Import List.
Import ListNotations.
From Coq Require Import Bool.

(* -------------------------------------------------------------------------
   Gateway Types
   ------------------------------------------------------------------------- *)

Inductive Role : Type :=
  | RoleAdmin
  | RoleAuditor
  | RoleUser.

Inductive Token : Type :=
  | ValidToken (role : Role)
  | InvalidToken.

Inductive Request : Type :=
  | MkRequest (id : nat) (tok : Token).

Inductive ProxyState : Type :=
  | Received
  | Authenticated
  | Audited
  | Forwarded
  | Rejected.

Record GatewayState : Type := MkGatewayState {
  req       : Request;
  state     : ProxyState;
  has_audit : bool
}.

(* -------------------------------------------------------------------------
   Well-Formedness
   ------------------------------------------------------------------------- *)

Definition has_valid_role (tok : Token) : bool :=
  match tok with
  | ValidToken RoleAdmin => true
  | ValidToken RoleAuditor => true
  | _ => false
  end.

Definition is_authorized (r : Request) : bool :=
  match r with
  | MkRequest _ tok => has_valid_role tok
  end.

Definition well_formed (g : GatewayState) : Prop :=
  match state g with
  | Received => has_audit g = false
  | Authenticated => is_authorized (req g) = true /\ has_audit g = false
  | Audited => is_authorized (req g) = true /\ has_audit g = true
  | Forwarded => is_authorized (req g) = true /\ has_audit g = true
  | Rejected => has_audit g = false
  end.

(* -------------------------------------------------------------------------
   Transitions
   ------------------------------------------------------------------------- *)

Definition init_gateway (r : Request) : GatewayState :=
  MkGatewayState r Received false.

Definition authenticate (g : GatewayState) : GatewayState :=
  match state g with
  | Received => 
      if is_authorized (req g) 
      then MkGatewayState (req g) Authenticated false
      else MkGatewayState (req g) Rejected false
  | _ => g
  end.

Definition generate_audit (g : GatewayState) : GatewayState :=
  match state g with
  | Authenticated => MkGatewayState (req g) Audited true
  | _ => g
  end.

Definition forward_request (g : GatewayState) : GatewayState :=
  match state g with
  | Audited => MkGatewayState (req g) Forwarded true
  | _ => g
  end.

(* -------------------------------------------------------------------------
   Theorems
   ------------------------------------------------------------------------- *)

Theorem init_well_formed : forall r, well_formed (init_gateway r).
Proof.
  intros r. unfold init_gateway. unfold well_formed. simpl. reflexivity.
Qed.

Theorem auth_preserves_wf : forall g, 
  well_formed g -> well_formed (authenticate g).
Proof.
  intros g Hwf.
  unfold authenticate.
  destruct (state g) eqn:Hst.
  - destruct (is_authorized (req g)) eqn:Hauth.
    + unfold well_formed. simpl. split.
      * exact Hauth.
      * reflexivity.
    + unfold well_formed. simpl. reflexivity.
  - exact Hwf.
  - exact Hwf.
  - exact Hwf.
  - exact Hwf.
Qed.

Theorem audit_preserves_wf : forall g,
  well_formed g -> well_formed (generate_audit g).
Proof.
  intros g Hwf.
  unfold generate_audit.
  destruct (state g) eqn:Hst.
  - exact Hwf.
  - unfold well_formed in *. rewrite Hst in Hwf. simpl.
    destruct Hwf as [Hauth _]. split.
    + exact Hauth.
    + reflexivity.
  - exact Hwf.
  - exact Hwf.
  - exact Hwf.
Qed.

Theorem forward_preserves_wf : forall g,
  well_formed g -> well_formed (forward_request g).
Proof.
  intros g Hwf.
  unfold forward_request.
  destruct (state g) eqn:Hst.
  - exact Hwf.
  - exact Hwf.
  - unfold well_formed in *. rewrite Hst in Hwf. simpl.
    destruct Hwf as [Hauth _]. split.
    + exact Hauth.
    + reflexivity.
  - exact Hwf.
  - exact Hwf.
Qed.

(* =========================================================================
   Invariant 1: Strict Isolation
   No request reaches Forwarded without being authorized via RoleAdmin or RoleAuditor.
   ========================================================================= *)
Theorem strict_isolation : forall g,
  well_formed g -> state g = Forwarded -> is_authorized (req g) = true.
Proof.
  intros g Hwf Hst.
  unfold well_formed in Hwf. rewrite Hst in Hwf.
  destruct Hwf as [Hauth Haudit]. exact Hauth.
Qed.

(* =========================================================================
   Invariant 2: Audit Irrefutability
   Every request that reaches the Forwarded state MUST have generated an audit log.
   ========================================================================= *)
Theorem audit_irrefutability : forall g,
  well_formed g -> state g = Forwarded -> has_audit g = true.
Proof.
  intros g Hwf Hst.
  unfold well_formed in Hwf. rewrite Hst in Hwf.
  destruct Hwf as [Hauth Haudit]. exact Haudit.
Qed.
