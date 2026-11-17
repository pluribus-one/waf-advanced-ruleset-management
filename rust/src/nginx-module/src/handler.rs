use std::ffi::c_void;
use std::ptr::null_mut;

use ngx::ffi::{NGX_DECLINED, NGX_ERROR, NGX_LOG_CRIT, NGX_LOG_ERR, ngx_http_core_run_phases, ngx_http_finalize_request, ngx_http_read_client_request_body, ngx_http_request_s};
use ngx::{
    core, http, ngx_log_error,
};

use ngx::http::{HTTPStatus, HttpModuleLocationConf};
use warm_ml::warm::WarmEvaluator;

use crate::module::WarmModuleConfig;
use crate::{
    NgxRequest, warm_instance,
};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RequestCtx {
    has_read_body: bool,
    is_async_read: bool,
    code: isize,
    raw_pointer: *mut Self,
}

/// NGINX access phase handler.
pub fn handle_request(request: &mut NgxRequest) -> core::Status {
    let raw_request: *mut ngx_http_request_s = request.into();
    let config = match crate::module::WarmModuleConfig::location_conf(request) {
        Some(config) => config,
        None => {
            ngx_log_error!(
                NGX_LOG_CRIT,
                request.log(),
                "Could not get location config in Warm module"
            );
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    // If warm module is disabled do nothing
    if config.enabled == 0 {
        return core::Status::NGX_DECLINED;
    }

    let module = <WarmModuleConfig as http::HttpModule>::module();
    let ctx: Option<&RequestCtx> = request.get_module_ctx::<RequestCtx>(module);

    //DEBUG
    ngx::ngx_log_error!(
        ngx::ffi::NGX_LOG_INFO,
        request.log(),
        "CTX: {:?}",
        &ctx
    );

    if ctx.is_none() || ctx.is_some_and(|v| !v.has_read_body) {  //Body has not been read yet
        // Start reading the body
        let rc = core::Status(unsafe { 
            ngx_http_read_client_request_body(raw_request, Some(request_body_handler)) 
        });

        //DEBUG
        ngx::ngx_log_error!(
            ngx::ffi::NGX_LOG_INFO,
            request.log(),
            "RC: {:?}",
            &rc
        );

        // If an error is given from ngx_http_read_client_request_body return it
        if rc.0 == NGX_ERROR as isize || rc >= HTTPStatus::SPECIAL_RESPONSE.into() {
            return rc
        }

        let ctx = request.get_module_ctx::<RequestCtx>(module);
        //DEBUG
        ngx::ngx_log_error!(
            ngx::ffi::NGX_LOG_INFO,
            request.log(),
            "CTX2: {:?}",
            &ctx
        );
        if ctx.is_none() || ctx.is_some_and(|v| !v.has_read_body) { //ngx_http_read_client_request_body called asynchronously
            set_ctx(request, None, None, Some(true));

            // With NGX_DONE the handlers tells to nginx that an asyncronous operation will handle this request
            return core::Status::NGX_DONE
        }

        let ctx = ctx.unwrap(); //Can't crash since it's checked in the if condition
        unsafe { ngx_http_finalize_request(raw_request, core::Status::NGX_DONE.into()) };
        core::Status(ctx.code)

    } else {    //Here body is read
        let ctx = ctx.unwrap(); //Can't crash since it's checked in the if condition

        //DEBUG
        ngx::ngx_log_error!(
            ngx::ffi::NGX_LOG_INFO,
            request.log(),
            "CTX3: {:?}",
            &ctx
        );

        unsafe { ngx_http_finalize_request(raw_request, core::Status::NGX_DONE.into()) };
        core::Status(ctx.code)
    } 
}

/// The handler called to read the request body. Here the request is parsed and evaluated with Warm.
extern "C" fn request_body_handler(raw_request: *mut ngx_http_request_s) {
    //SAFETY: raw_request is always NON-NULL
    let request: &mut NgxRequest = unsafe { NgxRequest::from_ngx_http_request(raw_request) };

    let module = <WarmModuleConfig as http::HttpModule>::module();
    let is_async: bool = request.get_module_ctx::<RequestCtx>(module).is_some_and(|v| v.is_async_read);

    // Retrieve the already initialized Warm instance.
    let warm =
        match warm_instance::get() {
            Some(instance) => instance,
            None => {
                ngx_log_error!(
                    NGX_LOG_CRIT,
                    request.log(),
                    "Could not get warm object in WARM module"
                );
                set_ctx(request, Some(true), Some(HTTPStatus::INTERNAL_SERVER_ERROR.0 as isize), None);
                handle_async_end(raw_request, is_async);
                return;
            }
        };

    // Build http::Request<String> from ngx_http_request_t
    let built_request = crate::convert::request::build_request(raw_request);

    let built_request =
        match built_request {
            Ok(request) => request,
            Err(error) => {
                ngx_log_error!(
                    NGX_LOG_ERR,
                    request.log(),
                    "WARM request conversion failed: {:?}",
                    error
                );

                set_ctx(request, Some(true), Some(HTTPStatus::BAD_REQUEST.0 as isize), None);
                handle_async_end(raw_request, is_async);
                return;
            }
        };

    let verdict = warm.evaluate(&built_request);
    
    //DEBUG: Shows the parsed request
    // ngx::ngx_log_error!(
    //     ngx::ffi::NGX_LOG_INFO,
    //     request.log(),
    //     "Request: {:?}",
    //     &built_request
    // );

    if verdict.is_malicious() {
        set_ctx(request, Some(true), Some(HTTPStatus::FORBIDDEN.0 as isize), None);
    } else {
        set_ctx(request, Some(true), Some(NGX_DECLINED as isize), None);
    }

    let ctx: Option<&RequestCtx> = request.get_module_ctx::<RequestCtx>(module);
    handle_async_end(raw_request, ctx.is_some_and(|v| v.is_async_read));
    
}

fn handle_async_end(raw_request: *mut ngx_http_request_s, is_async: bool){
    if is_async {
        unsafe {
            (*raw_request).write_event_handler = Some(ngx_http_core_run_phases);
            ngx_http_core_run_phases(raw_request);
        };
    }
}

/// Sets the request context with the specified data
fn set_ctx(request: &mut NgxRequest, has_read_body: Option<bool>, code: Option<isize>, is_async_read: Option<bool>){
    let module = <WarmModuleConfig as http::HttpModule>::module();
    let ctx = request.get_module_ctx::<RequestCtx>(module);

    if ctx.is_some() {
        let ctx = ctx.unwrap();
        let pointer = unsafe { &mut (*ctx.raw_pointer) as &mut RequestCtx }; //SAFETY: Always NON-NULL
        if let Some(v) = is_async_read {
            pointer.is_async_read = v;
        }
        if let Some(v) = has_read_body {
            pointer.has_read_body = v;
        }
        if let Some(v) = code {
            pointer.code = v;
        }
    } else {
        let new_ctx = RequestCtx {
            has_read_body: has_read_body.unwrap_or(false),
            code: code.unwrap_or(HTTPStatus::INTERNAL_SERVER_ERROR.0 as isize),
            is_async_read: is_async_read.unwrap_or(false),
            raw_pointer: null_mut(),
        };

        // Alloc RequestCtx struct in memory
        let p = request.pool().allocate(new_ctx);

        unsafe { (*p).raw_pointer = p; }

        let module = <WarmModuleConfig as http::HttpModule>::module();

        request.set_module_ctx(p as *mut c_void, module);
    }

}