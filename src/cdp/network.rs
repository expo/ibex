pub fn emit_request_will_be_sent(
    _http_request_id: u32,
    _url: &str,
    _method: &str,
    _headers: &[(String, String)],
    _post_data: Option<&[u8]>,
) {
}

pub fn emit_response(
    _http_request_id: u32,
    _status: u16,
    _response_headers: &[(String, String)],
    _body: &[u8],
) {
}

pub fn cleanup_request(_http_request_id: u32) {}
