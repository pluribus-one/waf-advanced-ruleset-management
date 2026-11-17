//! Matched rule message returned by [`crate::Transaction::matched_rules`].

/// Information about a rule that matched during transaction processing.
///
/// Obtained via [`crate::Transaction::matched_rules`] after calling any of
/// the `process_*` methods. This includes both disruptive rules (those that
/// trigger an intervention) and non-disruptive rules (e.g. `log,pass`).
#[derive(Debug, Clone)]
pub struct RuleMessage {
    /// Numeric rule ID from the `id` action in the SecRule definition.
    pub rule_id: i64,
    /// Processing phase in which the rule matched (internal phase index − 1):
    /// 0 = URI phase, 1 = request headers, 2 = request body,
    /// 3 = response headers, 4 = response body, 5 = logging.
    /// For standard SecRule phases the value equals the SecRule `phase:N` number minus 1.
    pub phase: i32,
    /// Raw severity value as defined by the rule's `severity` action.
    /// Defaults to `0` when the rule has no explicit severity action.
    pub severity: i32,
    /// Whether the rule triggered a disruptive action (block/deny/redirect).
    pub is_disruptive: bool,
    /// Human-readable message from the rule's `msg` action.
    pub message: String,
    /// Data captured by the `logdata` action, or empty if none.
    pub data: String,
    /// The actual value that triggered the match.
    pub matched: String,
    /// Reference string showing the variable name and transformation chain.
    pub reference: String,
    /// Path to the rules file that contains this rule.
    pub rule_file: String,
    /// Line number within [`rule_file`](Self::rule_file) where the rule is defined.
    pub rule_line: i32,
    /// Tags attached to the rule via `tag` actions.
    pub tags: Vec<String>,
}
