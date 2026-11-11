"""Visible simulation client. It never independently computes authorization."""

import os

import httpx
import streamlit as st

st.set_page_config(page_title="Policy Decision Lab", page_icon="🛡", layout="wide")
st.title("Zero Trust · Policy Decision Lab")
st.caption(
    "University simulation • request-time reevaluation • synthetic risk • no real authentication"
)
API = os.getenv("API_URL", "http://127.0.0.1:8000")


def get(path):
    response = httpx.get(API + path, timeout=10, trust_env=False)
    response.raise_for_status()
    return response.json()


def show(result):
    (st.success if result["decision"] == "ALLOW" else st.error)(
        result["decision"] + " · " + result["reason_code"]
    )
    st.write(result["decision_status"])
    st.write(result["explanation"])
    trace = result.get("trace") or {}
    st.write(
        "Strategy:",
        result.get("strategy", "validation failure"),
        "· Conflict:",
        result.get("conflict", False),
    )
    st.write("Effective policies: " + (", ".join(result.get("effective_policies", [])) or "none"))
    st.write("Winning policies: " + (", ".join(result.get("winning_policies", [])) or "none"))
    with st.expander("Resolved attributes and freshness"):
        st.json({key: trace.get(key) for key in ("attributes", "provenance", "failure")})
    with st.expander("Policy outcomes and individual conditions"):
        for row in trace.get("policy_outcomes", []):
            st.write(
                f"**{row['id']} — {row['outcome']}** · priority {row['priority']} · target={row['target_match']}"
            )
            st.json(row["conditions"], expanded=False)
    with st.expander("Complete decision trace"):
        st.json(trace)


try:
    health = get("/health")
    presets = get("/scenarios")
    subjects = get("/subjects")
    resources = get("/resources")
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"API unavailable: {exc}")
    st.stop()

if not health["simulation"]:
    st.warning(
        "Server simulation mode is disabled. Context controls cannot override trusted server context."
    )
if not health["opa_ready"]:
    st.warning(
        "OPA is unavailable or the expected policy engine is not loaded. Requests fail closed."
    )
if not subjects or not resources or not presets:
    st.error("Required demo data is empty. Publish the synthetic snapshots before continuing.")
    st.stop()
preset = st.selectbox(
    "Scenario preset", range(len(presets)), format_func=lambda index: presets[index]["name"]
)
base = presets[preset]["request"]
with st.form(f"request-{preset}"):
    left, right = st.columns(2)
    with left:
        subject_ids = [row["id"] for row in subjects]
        resource_ids = [row["id"] for row in resources]
        subject = st.selectbox(
            "Subject",
            subject_ids,
            index=subject_ids.index(base["subject_id"]) if base["subject_id"] in subject_ids else 0,
        )
        resource = st.selectbox(
            "Resource",
            resource_ids,
            index=resource_ids.index(base["resource_id"])
            if base["resource_id"] in resource_ids
            else 0,
        )
        action = st.selectbox("Action", ["read", "write", "delete"])
        baseline = st.selectbox("Baseline", ["context_abac", "static_abac", "rbac"])
        strategy = st.selectbox(
            "Combining strategy", ["deny-overrides", "permit-overrides", "priority-based"]
        )
    with right:
        trusted = st.checkbox("Trusted device", value=base["context"]["device_trusted"])
        location = st.selectbox(
            "Location",
            ["office", "vpn", "external"],
            index=["office", "vpn", "external"].index(base["context"]["location"]),
        )
        risk = st.slider("Synthetic risk score", 0, 100, base["context"]["risk_score"])
        time = st.text_input("Simulated time (ISO 8601 with timezone)", base["context"]["time"])
        compare = st.checkbox("Compare all three baselines", value=True)
        failure = st.selectbox(
            "Development failure injection",
            [
                "none",
                "opa_unavailable",
                "provider_unavailable",
                "stale_attribute",
                "invalid_opa_response",
                "opa_timeout",
                "undefined_result",
                "invalid_policy",
                "missing_attribute",
                "malformed_request",
            ]
            if health["failure_injection"]
            else ["none"],
        )
    submitted = st.form_submit_button("Evaluate access", type="primary")

if submitted:
    payload = {
        "subject_id": subject,
        "resource_id": resource,
        "action": action,
        "baseline": baseline,
        "strategy": strategy,
        "trace": True,
        "failure_mode": failure if failure != "malformed_request" else "none",
    }
    if health["simulation"]:
        payload["context"] = {
            "device_trusted": trusted,
            "location": location,
            "time": time,
            "risk_score": risk,
        }
    if failure == "malformed_request":
        payload["action"] = "execute"
    models = ["rbac", "static_abac", "context_abac"] if compare else [baseline]
    for column, model in zip(st.columns(len(models)), models):
        with column:
            st.subheader(model)
            try:
                response = httpx.post(
                    API + "/evaluate",
                    json={**payload, "baseline": model},
                    timeout=15,
                    trust_env=False,
                )
                show(response.json())
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                st.error(f"No trustworthy decision available. Protected content withheld. {exc}")
