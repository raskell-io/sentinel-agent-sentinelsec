//! Behavioural checks against the underlying zentinel-modsec engine.
//!
//! The agent's own tests cover its configuration and protocol surface, but the
//! thing operators actually depend on is which requests get blocked. That is
//! decided by the engine, so a version bump there can change security
//! behaviour without touching a line of this crate.
//!
//! These ran green across the 0.1.4 -> 0.2.0 bump, which changed chain
//! evaluation (zentinel-modsec#18).

use zentinel_modsec::ModSecurity;

fn blocked(rules: &str, uri: &str, method: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

/// A chain is one logical rule: every link must match before it blocks.
#[test]
fn chained_rule_requires_every_link() {
    let rules = "SecRuleEngine On\n\
        SecRule REQUEST_URI \"@contains admin\" \"id:1001,phase:1,deny,chain\"\n\
        SecRule REQUEST_METHOD \"@streq POST\"";

    assert!(
        blocked(rules, "/admin", "POST"),
        "complete chain should block"
    );
    assert!(
        !blocked(rules, "/admin", "GET"),
        "partial chain match must not block — this is the false positive \
         zentinel-modsec#18 fixed"
    );
}

#[test]
fn sqli_is_detected_and_clean_traffic_passes() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@detectSQLi\" \"id:2001,phase:2,deny\"";

    assert!(blocked(rules, "/?q=1' OR '1'='1--", "GET"));
    assert!(!blocked(rules, "/?q=hello", "GET"));
}

/// The anomaly-scoring path CRS is built around: macro-expanded thresholds
/// and `setvar` deltas both have to work for scoring to accumulate.
#[test]
fn anomaly_scoring_reaches_the_threshold() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:3001,phase:1,pass,nolog,setvar:tx.threshold=5\"\n\
        SecRule ARGS \"@detectXSS\" \"id:3002,phase:2,pass,setvar:'tx.score=+5'\"\n\
        SecRule TX:score \"@ge %{tx.threshold}\" \"id:3003,phase:2,deny\"";

    assert!(blocked(rules, "/?q=<script>alert(1)</script>", "GET"));
    assert!(!blocked(rules, "/?q=hello", "GET"));
}
