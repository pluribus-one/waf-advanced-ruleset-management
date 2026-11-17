#include <modsecurity/transaction.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/rule_with_actions.h>
#include <modsecurity/rule.h>

#include <cstdint>
#include <vector>

extern "C" {

/// Borrowed view of a matched rule, passed to the callback by msc_iterate_rules_messages.
/// All string pointers are valid only for the duration of the callback.
struct MscRuleMessageView {
    int64_t  rule_id;
    int32_t  phase;
    int32_t  severity;
    int32_t  is_disruptive;
    int32_t  rule_line;
    const char *message;
    const char *data;
    const char *match_string;
    const char *reference;
    const char *rule_file;
    const char * const *tags;
    size_t   tags_count;
};

typedef void (*MscRuleMessageCb)(void *ctx, const MscRuleMessageView *view);

/// Iterates over all matched rule messages recorded in the transaction and
/// invokes `cb` once per message.
///
/// The callback receives a `MscRuleMessageView` whose string pointers are
/// valid only for that single invocation. `ctx` is forwarded to the callback
/// unchanged and may be null.
///
/// Does nothing if `tx` or `cb` is null, or if `tx` has no matched rule messages.
void msc_iterate_rules_messages(
    modsecurity::Transaction *tx,
    MscRuleMessageCb cb,
    void *ctx)
{
    if (!tx || !cb) {
        return;
    }

    for (const auto &rm : tx->m_rulesMessages) {
        // Collect raw pointers to each tag string; valid as long as rm.m_tags is alive
        std::vector<const char *> tag_ptrs;
        tag_ptrs.reserve(rm.m_tags.size());
        for (const auto &tag : rm.m_tags) {
            tag_ptrs.push_back(tag.c_str());
        }

        MscRuleMessageView view{};
        view.rule_id       = rm.m_rule.m_ruleId;
        view.phase         = rm.getPhase();
        view.severity      = rm.m_severity;
        view.is_disruptive = rm.m_isDisruptive ? 1 : 0;
        view.rule_line     = rm.m_rule.getLineNumber();
        view.message       = rm.m_message.c_str();
        view.data          = rm.m_data.c_str();
        view.match_string  = rm.m_match.c_str();
        view.reference     = rm.m_reference.c_str();
        view.rule_file     = rm.m_rule.getFileName().c_str();
        view.tags          = tag_ptrs.empty() ? nullptr : tag_ptrs.data();
        view.tags_count    = tag_ptrs.size();

        cb(ctx, &view);
        // tag_ptrs goes out of scope here; its string pointers are no longer
        // reachable after this point.
    }
}

} // extern "C"
