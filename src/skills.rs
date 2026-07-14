//! Curated, hand-written guidance per core resource type: what it is, how it
//! fits into the SOC 2 compliance journey, and which other resources it's
//! commonly used alongside. This is content Kiln's own OpenAPI spec doesn't
//! (and structurally can't) capture - it's narrative/workflow knowledge, not
//! a filter or attribute list - so it's embedded at compile time from
//! skills/*.md rather than fetched live. Grounded in the klaay-api skill's
//! workflows.md and real model associations, not invented.
//!
//! Covers the ~20 resources central to the SOC 2 journey, not all ~100+
//! resource types the API exposes - peripheral resources (templates, feedback
//! records, etc.) fall back to spec-derived info only in `describe`. Extend
//! this list by adding a new skills/<resource>.md and a match arm below.

pub(crate) fn lookup(resource: &str) -> Option<&'static str> {
    match resource {
        "accounts" => Some(include_str!("../skills/accounts.md")),
        "account_information_answers" => {
            Some(include_str!("../skills/account_information_answers.md"))
        }
        "account_users" => Some(include_str!("../skills/account_users.md")),
        "collected_evidence_selected_controls" => Some(include_str!(
            "../skills/collected_evidence_selected_controls.md"
        )),
        "collected_evidences" => Some(include_str!("../skills/collected_evidences.md")),
        "compliance_stats" => Some(include_str!("../skills/compliance_stats.md")),
        "conversations" => Some(include_str!("../skills/conversations.md")),
        "devices" => Some(include_str!("../skills/devices.md")),
        "evidence_checks" => Some(include_str!("../skills/evidence_checks.md")),
        "framework_selections" => Some(include_str!("../skills/framework_selections.md")),
        "incidents" => Some(include_str!("../skills/incidents.md")),
        "messages" => Some(include_str!("../skills/messages.md")),
        "policies" => Some(include_str!("../skills/policies.md")),
        "policy_versions" => Some(include_str!("../skills/policy_versions.md")),
        "selected_controls" => Some(include_str!("../skills/selected_controls.md")),
        "selected_risk_scenarios" => Some(include_str!("../skills/selected_risk_scenarios.md")),
        "tasks" => Some(include_str!("../skills/tasks.md")),
        "teams" => Some(include_str!("../skills/teams.md")),
        "users" => Some(include_str!("../skills/users.md")),
        "vendors" => Some(include_str!("../skills/vendors.md")),
        "workstreams" => Some(include_str!("../skills/workstreams.md")),
        _ => None,
    }
}
