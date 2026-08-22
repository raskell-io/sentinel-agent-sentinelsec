//! Behavioural checks against the underlying zentinel-modsec engine.
//!
//! The agent's own tests cover its configuration and protocol surface, but the
//! thing operators actually depend on is which requests get blocked. That is
//! decided by the engine, so a version bump there can change security
//! behaviour without touching a line of this crate.
//!
//! These ran green across the 0.1.4 -> 0.2.0 bump, which changed chain
//! evaluation (zentinel-modsec#18), and the 0.2.0 -> 0.3.0 bump, which added
//! JSON body inspection (zentinel-modsec#24).

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

/// A body-carrying request, which the helper above does not cover.
fn blocked_with_body(rules: &str, content_type: &str, body: &[u8]) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api/search", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", content_type).unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

const ARGS_SQLI: &str = "SecRuleEngine On\n\
    SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,deny,status:403\"";

/// The reason for the 0.3.0 bump.
///
/// Before zentinel-modsec#24 a JSON body fell through to the urlencoded
/// parser, so `ARGS` was empty for every JSON request and this rule had
/// nothing to inspect. This agent is deployed in front of APIs that are
/// overwhelmingly JSON, so that was most of the traffic it was meant to
/// protect.
#[test]
fn sqli_in_a_json_body_is_blocked() {
    let payload = br#"{"q":"1 UNION SELECT password FROM users"}"#;
    assert!(
        blocked_with_body(ARGS_SQLI, "application/json", payload),
        "SQLi in a JSON body must be detected"
    );
}

/// The control: the same payload in a form body. If this ever fails, the test
/// above proves nothing about JSON specifically.
#[test]
fn sqli_in_a_form_body_is_blocked() {
    assert!(blocked_with_body(
        ARGS_SQLI,
        "application/x-www-form-urlencoded",
        b"q=1 UNION SELECT password FROM users"
    ));
}

#[test]
fn sqli_nested_inside_a_json_object_is_blocked() {
    let payload = br#"{"filter":{"where":{"name":"1 UNION SELECT password FROM users"}}}"#;
    assert!(blocked_with_body(ARGS_SQLI, "application/json", payload));
}

/// Clean JSON must still pass. A body processor that blocked everything would
/// satisfy the tests above and be useless in production.
#[test]
fn clean_json_traffic_is_not_blocked() {
    let payload = br#"{"q":"laptop","page":2,"in_stock":true}"#;
    assert!(!blocked_with_body(ARGS_SQLI, "application/json", payload));
}

/// An empty body with a JSON content type is routine on POST and DELETE and
/// must not be treated as a parse failure — a CRS ruleset with rule 200002
/// would otherwise reject those requests.
#[test]
fn an_empty_json_body_does_not_trip_the_body_error_rule() {
    let crs_200002 = "SecRuleEngine On\n\
        SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";
    assert!(!blocked_with_body(crs_200002, "application/json", b""));
}
