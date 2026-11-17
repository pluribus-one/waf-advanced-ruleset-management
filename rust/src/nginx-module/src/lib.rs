pub mod commands;
pub mod config;
pub mod convert;
pub mod handler;
pub mod module;
pub mod warm_instance;

pub use module::NGX_HTTP_WARM_MODULE;

pub type NgxRequest = ngx::http::Request;

ngx::ngx_modules!(NGX_HTTP_WARM_MODULE);