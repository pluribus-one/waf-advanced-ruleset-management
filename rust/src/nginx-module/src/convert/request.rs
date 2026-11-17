use std::str::FromStr;

use http::{
    Request,
    Method,
    Uri,
};

use ngx::{ffi::{NGX_LOG_DEBUG, ngx_http_request_t}, ngx_log_error};

use crate::{NgxRequest, convert::{
    body::{BodyReadError, convert_body}, headers::convert_headers, request::RequestConversionError::InvalidUri, version::convert_version
}};


#[derive(Debug)]
pub enum RequestConversionError {
    InvalidRequest,
    InvalidMethod,
    InvalidUri(String),
    InvalidBody(BodyReadError)
}


/// Build a Rust HTTP request from nginx request data.
///
/// Converts ngx_http_request_t into http::Request<String>
///
/// The body is expected to be ready for reading it
pub fn build_request(
    raw_request: *mut ngx_http_request_t
) -> Result<Request<String>, RequestConversionError> {

    if raw_request.is_null() {
        return Err(RequestConversionError::InvalidRequest);
    }

    let request = unsafe { &*raw_request };

    let body = convert_body(request)?;

    let method = convert_method(request)?;
    let uri = convert_uri(request)?;
    let version = convert_version(request.http_version);

    // DEBUG
    let req = unsafe { NgxRequest::from_ngx_http_request(raw_request) };
    ngx_log_error!(
        NGX_LOG_DEBUG,
        req.log(),
        "URI: {uri}"
    );

    let headers = convert_headers(request);

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(version);

    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }

    builder
        .body(body)
        .map_err(|_| RequestConversionError::InvalidRequest)
}


/// Convert nginx request method.
///
/// nginx stores the method as a numeric value.
/// The final mapping depends on the constants exposed
/// by the ngx crate version.
fn convert_method(
    request: &ngx_http_request_t,
) -> Result<Method, RequestConversionError> {


    match request.method_name.to_str() {

        Ok(method) => {

            Method::from_bytes(
                method.as_bytes()
            )
            .map_err(|_| {
                RequestConversionError::InvalidMethod
            })
        }


        Err(_) => {

            Err(
                RequestConversionError::InvalidMethod
            )
        }
    }
}


/// Convert nginx URI.
///
/// The query string must be preserved.
///
/// Example:
///
/// /login?id=10
///
/// must not become:
///
/// /login
fn convert_uri(
    request: &ngx_http_request_t,
) -> Result<Uri, RequestConversionError> {
    let uri = request.unparsed_uri.to_string();

    http::Uri::from_str(&uri).map_err(|_| InvalidUri(uri))
}