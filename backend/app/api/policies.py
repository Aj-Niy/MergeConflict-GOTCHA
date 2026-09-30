from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import Policy, User
from app.schemas.policy import PolicyCreate, PolicyUpdate, PolicyOut
from app.auth.dependencies import get_current_user, get_optional_current_user
from app.policies.policy_engine import DEFAULT_SECURITY_POLICY

router = APIRouter(prefix="/policy", tags=["Policies"])

@router.get("", response_model=List[PolicyOut])
def list_policies(
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Policy)
    if current_user:
        query = query.filter((Policy.user_id == current_user.id) | (Policy.is_default == True))
    else:
        query = query.filter(Policy.is_default == True)
    
    policies = query.order_by(Policy.created_at.desc()).all()
    if not policies:
        # Seed default policy
        default_p = Policy(
            name="Default Zero-Trust Policy",
            description="Strict policy blocking undisclosed shells, command execution, and token exfiltration.",
            rules_json=DEFAULT_SECURITY_POLICY,
            is_default=True
        )
        db.add(default_p)
        db.commit()
        db.refresh(default_p)
        policies = [default_p]

    return [PolicyOut.model_validate(p) for p in policies]

@router.post("", response_model=PolicyOut)
def create_policy(
    policy_in: PolicyCreate,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    policy = Policy(
        user_id=current_user.id if current_user else None,
        name=policy_in.name,
        description=policy_in.description,
        rules_json=policy_in.rules_json,
        is_default=policy_in.is_default
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return PolicyOut.model_validate(policy)

@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db)
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return PolicyOut.model_validate(policy)

@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str,
    policy_in: PolicyUpdate,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    if current_user and policy.user_id and policy.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this policy")

    if policy_in.name is not None:
        policy.name = policy_in.name
    if policy_in.description is not None:
        policy.description = policy_in.description
    if policy_in.rules_json is not None:
        policy.rules_json = policy_in.rules_json
    if policy_in.is_default is not None:
        policy.is_default = policy_in.is_default

    db.commit()
    db.refresh(policy)
    return PolicyOut.model_validate(policy)

@router.delete("/{policy_id}")
def delete_policy(
    policy_id: str,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    if current_user and policy.user_id and policy.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this policy")

    db.delete(policy)
    db.commit()
    return {"message": "Policy deleted successfully"}
