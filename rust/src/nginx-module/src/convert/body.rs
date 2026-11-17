use ngx::ffi::{
    ngx_chain_t,
    ngx_http_request_t,
};

use crate::convert::request::RequestConversionError::{self, InvalidBody};


#[derive(Debug)]
pub enum BodyReadError {
    MissingRequestBody,
    InvalidUtf8,
    InvalidBuffer,
}

pub fn convert_body(request: &ngx_http_request_t) -> Result<String, RequestConversionError> {

    //TODO: Body can be unbuffered

    let request_body = unsafe { request.request_body.as_ref().ok_or(InvalidBody(BodyReadError::MissingRequestBody)) }?;
    let mut bytes: Vec<u8> = Vec::new();

    let mut chain: *mut ngx_chain_t = request_body.bufs;

    while !chain.is_null() {
        let buf = unsafe { (*chain).buf };

        if !buf.is_null() {
            let buf = unsafe { &*buf };

            if !buf.pos.is_null() && !buf.last.is_null()
            {
                let len = unsafe { buf.last.offset_from(buf.pos) };

                if len < 0 {
                    return Err(InvalidBody(BodyReadError::InvalidBuffer));
                }

                let len = len as usize;

                if len > 0 {
                    let slice = unsafe { std::slice::from_raw_parts(buf.pos, len) };
                    bytes.extend_from_slice(slice);
                }
            }
        }

        chain = unsafe { (*chain).next };
    }

    String::from_utf8(bytes).map_err(|_| InvalidBody(BodyReadError::InvalidUtf8))
}