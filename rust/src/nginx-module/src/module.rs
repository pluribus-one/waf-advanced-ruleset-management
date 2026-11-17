use std::os::raw::c_void;
use std::ptr::null;

use ngx::{core};

use ngx::ffi::{
    NGX_CONF_UNSET, NGX_HTTP_MODULE, NGX_LOG_EMERG, ngx_array_push, ngx_conf_t, ngx_http_handler_pt, ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t, ngx_uint_t,
};

use ngx::http::{
    HttpModule, HttpModuleLocationConf, HttpModuleMainConf, NgxHttpCoreModule,
};

use crate::commands::NGX_HTTP_WARM_COMMANDS;
use crate::config::{WarmLocationConfig, WarmMainConfig};
use crate::warm_instance;
use ngx::http_request_handler;

/// Warm HTTP module.
pub struct WarmModuleConfig;

unsafe impl HttpModuleMainConf for WarmModuleConfig {
    type MainConf = WarmMainConfig;
}


unsafe impl HttpModuleLocationConf for WarmModuleConfig {
    type LocationConf = WarmLocationConfig;
}

http_request_handler!(
    warm_request_handler,
    |request: &mut crate::NgxRequest| {
        crate::handler::handle_request(request)
    }
);

impl HttpModule for WarmModuleConfig {

    fn module() -> &'static ngx_module_t {
        unsafe {
            &*std::ptr::addr_of!(NGX_HTTP_WARM_MODULE)
        }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        // SAFETY: this function is called with non-NULL cf always
        let cf = unsafe { &mut *cf };
        let cmcf = NgxHttpCoreModule::main_conf_mut(cf).expect("http core main conf");

        let h = unsafe { ngx_array_push(
            &mut cmcf.phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
        ) } as *mut ngx_http_handler_pt;
        
        if h.is_null() {
            return core::Status::NGX_ERROR.into();
        }

        // set an Access phase handler
        unsafe { *h = Some(warm_request_handler) };

        core::Status::NGX_OK.into()
    }

    unsafe extern "C" fn init_main_conf(parser_conf: *mut ngx_conf_t, main_conf: *mut c_void) -> *mut std::ffi::c_char
    {
        if !main_conf.is_null() {
            let main_conf: &WarmMainConfig = unsafe { &mut *(main_conf as *mut WarmMainConfig) };
            let parser_conf = unsafe { &*parser_conf };

            warm_instance::init(main_conf).map_or_else(
                |err| {
                    ngx::ngx_log_error!(
                        NGX_LOG_EMERG,
                        parser_conf.log,
                        "Initialization failed. This error is caused by: {:?}",
                        err
                    );

                    core::NGX_CONF_ERROR
                }, 
                |_| core::NGX_CONF_OK
            )
        } else {
            core::NGX_CONF_ERROR
        }
    }

    unsafe extern "C" fn create_loc_conf(cf: *mut ngx_conf_t) -> *mut c_void {
        //SAFETY: This function is never called in the project code so assuming that nginx doesn't give a NULL pointer for `cf`
        let pool = unsafe { core::Pool::from_ngx_pool((*cf).pool) };
        let config = WarmLocationConfig {
            enabled: NGX_CONF_UNSET as ngx::ffi::ngx_flag_t
        };
        pool.allocate::<WarmLocationConfig>(config) as *mut c_void
    }   
}

static NGX_HTTP_WARM_MODULE_CTX: ngx_http_module_t =
    ngx_http_module_t {
        preconfiguration: Some(WarmModuleConfig::preconfiguration),
        postconfiguration: Some(WarmModuleConfig::postconfiguration),

        create_main_conf: Some(WarmModuleConfig::create_main_conf),
        init_main_conf: Some(WarmModuleConfig::init_main_conf),

        create_srv_conf: None,
        merge_srv_conf: None,

        create_loc_conf: Some(WarmModuleConfig::create_loc_conf),
        merge_loc_conf: None,
    };

pub static mut NGX_HTTP_WARM_MODULE: ngx_module_t =
    ngx_module_t {
        ctx: &raw const NGX_HTTP_WARM_MODULE_CTX as _,
        commands: unsafe {
            &raw mut NGX_HTTP_WARM_COMMANDS[0]
        },
        type_: NGX_HTTP_MODULE as ngx_uint_t,
        ..ngx_module_t::default()
    };