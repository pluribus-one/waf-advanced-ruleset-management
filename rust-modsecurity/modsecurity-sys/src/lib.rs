#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//! Low-level FFI bindings to the C [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.

pub mod bindings;

pub use bindings::*;

use std::ffi::c_void;
use std::os::raw::c_char;

/// A read-only view of a single matched rule message, valid only for the
/// duration of the [`MscRuleMessageCb`] callback invocation that receives it.
///
/// All `*const c_char` fields point into live C++ `std::string` objects for
/// the duration of the callback. `tags` is null when `tags_count` is zero.
///
/// This struct **must** match the layout of `MscRuleMessageView` in
/// `transaction_ext.cpp` exactly. Both sides use C layout rules.
#[repr(C)]
pub struct MscRuleMessageView {
    pub rule_id: i64,
    pub phase: i32,
    pub severity: i32,
    pub is_disruptive: i32,
    pub rule_line: i32,
    pub message: *const c_char,
    pub data: *const c_char,
    pub match_string: *const c_char,
    pub reference: *const c_char,
    pub rule_file: *const c_char,
    /// One pointer per tag. Null when `tags_count` is zero.
    pub tags: *const *const c_char,
    pub tags_count: usize,
}

/// Callback type passed to [`msc_iterate_rules_messages`].
///
/// Callback invoked once per matched rule by [`msc_iterate_rules_messages`].
/// `view` is only valid for the duration of that single call.
pub type MscRuleMessageCb =
    Option<unsafe extern "C" fn(ctx: *mut c_void, view: *const MscRuleMessageView)>;

extern "C" {
    /// Iterates over all matched rule messages in the transaction, invoking
    /// `cb` once per message.
    ///
    /// Does nothing if `transaction` or `cb` is null. `ctx` is forwarded to
    /// the callback unchanged.
    pub fn msc_iterate_rules_messages(
        transaction: *mut Transaction,
        cb: MscRuleMessageCb,
        ctx: *mut c_void,
    );
}

// TODO: Write sanity test
