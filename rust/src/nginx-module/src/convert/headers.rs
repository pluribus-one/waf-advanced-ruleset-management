use http::HeaderMap;

use ngx::ffi::{
    ngx_http_request_t, ngx_table_elt_t,
};


/// Convert all nginx request headers into a Rust HeaderMap.
///
/// Every received header is copied.
///
/// The converter does not restrict itself to:
///
/// - Host
/// - User-Agent
/// - Content-Type
///
/// Any valid nginx header is preserved.
pub fn convert_headers(request: &ngx_http_request_t) -> HeaderMap {

    let mut headers = HeaderMap::new();
    
    let headers_in: &ngx::ffi::ngx_http_headers_in_t = &request.headers_in;
 
    let mut part = &headers_in.headers.part;
    let mut v: *mut ngx_table_elt_t = part.elts as *mut ngx_table_elt_t;
    let mut i = 0;

    //https://nginx.org/en/docs/dev/development_guide.html#adding_new_modules:~:text=To%20iterate%20over%20the%20items%2C%20directly%20access%20the%20list%20fields%20as%20shown%20in%20the%20example%3A

    loop {
        if i >= part.nelts {
            if part.next.is_null() {
                break
            }

            // SAFETY: Checked before
            part = unsafe { &mut *part.next };
            v = part.elts as *mut ngx_table_elt_t;
            i = 0;
        }

        if !v.is_null() {
            let count = part.nelts;
            
            for element_counter in 0..count {
                let header: &ngx::ffi::ngx_table_elt_s = unsafe { &*v.add(element_counter) };

                if header.key.len == 0 {
                    continue;
                }

                let key = http::header::HeaderName::from_bytes(header.key.as_bytes());
                let value = http::header::HeaderValue::from_str(&header.value.to_string());

                if key.is_err() || value.is_err() {
                    continue;
                }

                let key = key.unwrap();
                let value = value.unwrap();

                headers.insert(key, value);
            } 
        }

        i += 1;
    }


    headers
}