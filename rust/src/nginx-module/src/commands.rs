use std::{
    ffi::{c_char, c_void}, mem::offset_of,
};

use ngx::{
    core, ffi::{
        NGX_CONF_FLAG, NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET, NGX_LOG_EMERG, ngx_command_t, ngx_conf_t, ngx_flag_t, ngx_str_t, ngx_uint_t,
    }, ngx_conf_log_error, ngx_string,
};

use crate::{config::{WarmLocationConfig, WarmMainConfig}, };

/// NGINX directives supported by the module.
#[used]
pub static mut NGX_HTTP_WARM_COMMANDS: [ngx_command_t; 5] = [

    //
    // warm on;
    // warm off;
    //
    ngx_command_t {
        name: ngx_string!("warm"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_FLAG) as ngx_uint_t,
        set: Some(ngx::ffi::ngx_conf_set_flag_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: offset_of!(WarmLocationConfig, enabled),
        post: std::ptr::null_mut(),
    },


    //
    // warm_load_rules /path;
    //
    ngx_command_t {
        name: ngx_string!("warm_load_rules"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_rules_directory),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },


    //
    // warm_load_config /path;
    //
    ngx_command_t {
        name: ngx_string!("warm_load_config"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_config_file),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },


    //
    // warm_load_model /path;
    //
    ngx_command_t {
        name: ngx_string!("warm_load_model"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_model_file),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },

    ngx_command_t::empty(),
];

/// Parse:
///
/// warm_load_rules /opt/warm/rules;
///
/// Used only during Warm bootstrap.
extern "C" fn set_rules_directory(cf: *mut ngx_conf_t, _cmd: *mut ngx_command_t, conf: *mut c_void) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut WarmMainConfig) };

    let path =
        match parse_path_argument(cf) {

            Ok(path) => path,

            Err(error) => {

                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "{}",
                    error
                );

                return core::NGX_CONF_ERROR;
            }
        };


    conf.rules_dir = Some(path);

    core::NGX_CONF_OK
}



/// Parse:
///
/// warm_load_config /etc/warm/config.yaml;
///
/// Can be declared multiple times.
extern "C" fn set_config_file(cf: *mut ngx_conf_t, _cmd: *mut ngx_command_t, conf: *mut c_void) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut WarmMainConfig) };

    let path =
        match parse_path_argument(cf) {

            Ok(path) => path,

            Err(error) => {

                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "{}",
                    error
                );

                return core::NGX_CONF_ERROR;
            }
        };

    conf.config_files.push(path);

    core::NGX_CONF_OK
}



/// Parse:
///
/// warm_load_model /opt/warm/model.bin;
///
/// Used only during Warm bootstrap.
extern "C" fn set_model_file(cf: *mut ngx_conf_t, _cmd: *mut ngx_command_t, conf: *mut c_void) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut WarmMainConfig) };

    let path =
        match parse_path_argument(cf) {

            Ok(path) => path,

            Err(error) => {

                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "{}",
                    error
                );

                return core::NGX_CONF_ERROR;
            }
        };

    conf.model = Some(path);

    core::NGX_CONF_OK
}



/// Extract the first directive argument.
///
/// Example:
///
/// warm_load_model /opt/model.bin;
///
/// args[0] -> directive name
/// args[1] -> value
fn parse_path_argument(cf: *mut ngx_conf_t) -> Result<String, &'static str> {
    if cf.is_null() {
        return Err("invalid nginx configuration");
    }

    let args: &[ngx_str_t] = unsafe { (*(*cf).args).as_slice() };

    if args.len() < 2 {
        return Err("missing directive argument");
    }

    let value =
        args[1]
            .to_str()
            .map_err(|_| {
                "directive argument is not UTF-8"
            })?;


    if value.is_empty() {
        return Err("directive argument is empty");
    }

    Ok(value.to_string())
}