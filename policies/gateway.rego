package gateway

import rego.v1

contract := "gateway-5.0.0"
resource_columns := {
    "customers": ["id", "department", "name", "email", "salary", "national_id"],
    "financial": ["id", "department", "period", "revenue"],
    "production": ["id", "department", "event", "severity"],
}

mask := ["email", "salary", "national_id"] if {
    input.attributes.resource.id == "customers"
    input.attributes.subject.role != "admin"
} else := ["email", "salary", "national_id"] if {
    input.attributes.resource.id == "customers"
    input.view.mask_admin
} else := []

scope := {"kind": "all"} if {
    input.attributes.subject.role == "admin"
} else := {"kind": "department", "value": input.attributes.subject.department}

# ONE OPA transaction. The validated deny-overrides result gates execution.
evaluation := {
    "revision": input.revision,
    "engine_revision": data.deployment.engine_revision,
    "contract": contract,
    "outcomes": data.capstone.outcomes,
    "plan": {
        "version": 1,
        "policy_revision": input.revision,
        "tenant_id": input.attributes.subject.tenant_id,
        "resource": input.attributes.resource.id,
        "columns": resource_columns[input.attributes.resource.id],
        "mask": mask,
        "row_scope": scope,
        "limit": input.view.limit,
    },
} if {
    input.engine_revision == data.deployment.engine_revision
    input.attributes.resource.id in {"customers", "financial", "production"}
}
