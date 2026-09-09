use std::{collections::HashMap};
use ndarray::{Array1};
use warm_ml::{WarmDatasetFileReader};
use warm_ml::waf_engines::*;
use http::{Method, Request};
use warm_ml::*;

#[allow(dead_code)]
pub struct ModsecLearnReader;
impl WarmDatasetFileReader for ModsecLearnReader {
    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<String> = WarmDatasetFileReaderHelper::parse_json(file);
        let mut requests = Array1::<Request<String>>::default(samples.len());

        for (i, sample) in samples.iter().enumerate() {
            requests[i] = Request::builder()
                .uri(format!("/?{sample}"))
                .version(http::Version::HTTP_11)
                .method(Method::GET)
                .body(String::new())
                .expect(format!("Error while building request. Can happen if given sample {sample} is not url encoded").as_str());
        }
        
        requests
    }
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
//A modified version of https://github.com/Morzeux/HttpParamsDataset/blob/master/payload_full.csv
pub struct HttpParamsDatasetReader{
    payload: String,
    length: String,
    attack_type: String,
    label: String,
}
impl WarmDatasetFileReader for HttpParamsDatasetReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>> {
        let samples: Vec<Self> = WarmDatasetFileReaderHelper::parse_json(file);
        
        // Encode every payload
        let samples: Vec<String> = samples.iter().map(|v| {
            urlencoding::encode(v.payload.as_str()).into_owned()
        }).collect();
        
        let mut requests = Array1::<Request<String>>::default(samples.len());

        // For each sample create a Request and put it in `requests`
        for (i, sample) in samples.iter().enumerate() {
            requests[i] = Request::builder()
                .uri(format!("/?p={sample}"))
                .version(http::Version::HTTP_11)
                .method(Method::GET)
                .body(String::new())
                .expect(format!("Error while building request. Can happen if given sample {sample} is not url encoded").as_str());
        }
        
        requests
    }
}



#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
//https://huggingface.co/datasets/darkknight25/polyglot_paylods_datasets
pub struct PolyglotJsonReader{
    payload: String,
    attack_type: String,
    description: String,
}

impl WarmDatasetFileReader for PolyglotJsonReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmDatasetFileReaderHelper::parse_jsonl(file);

        let mut requests = Array1::<Request<String>>::default(samples.len()*2);

        // For each sample create a Request and put it in `requests`
        for (i, sample) in samples.iter().enumerate() {    
            // Url encode the payload
            let payload = urlencoding::encode(&sample.payload).into_owned();

            // Create GET request
            let get_req = Request::builder()
            .uri(format!("/?p={payload}"))
            .version(http::Version::HTTP_11)
            .method(Method::GET)
            .body(String::new())
            .expect("Error while building request. Can happen if given sample {payload} is not url encoded");

            // Create POST request
            let post_req = Request::builder()
            .uri(format!("/test_post"))
            .version(http::Version::HTTP_11)
            .method(Method::POST)
            .body(payload)
            .expect("Error while building request.");
    
            requests[i] = get_req;
            requests[i+1] = post_req;
        }
        
        requests
    }
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
//https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset
pub struct WebPayloadsJsonReader{
    id: String,
    description: String,
    payload: String,
    context: String,
    attack_type: String,
    severity: String,
}
impl WarmDatasetFileReader for WebPayloadsJsonReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmDatasetFileReaderHelper::parse_json(file);
        
        // Get requests array from samples
        let mut requests = Array1::<Request<String>>::default(samples.len()*2);

        for (i, sample) in samples.iter().enumerate() {
            // Url encode the payload
            let payload = urlencoding::encode(&sample.payload).into_owned();

            // Create GET request
            let get_req = Request::builder()
            .uri(format!("/?p={payload}"))
            .version(http::Version::HTTP_11)
            .method(Method::GET)
            .body(String::new())
            .expect("Error while building request. Can happen if given sample {payload} is not url encoded");

            // Create POST request
            let post_req = Request::builder()
            .uri(format!("/test_post"))
            .version(http::Version::HTTP_11)
            .method(Method::POST)
            .body(payload)
            .expect("Error while building request.");
    
            requests[i] = get_req;
            requests[i+1] = post_req;
        }

        requests
    }
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct MsanCSVData{
    id: String,
    timestamp: String,
    client_addr: String,
    client_port: String,
    method: String,
    uri: String,
    request_protocol: String,
    request_headers: String,
    request_body: String,
    server_addr: String,
    server_port: String,
    response_code: String,
    response_protocol: String,
    response_headers: String,
    response_body: String,
    http_raw_text: String,
}

impl MsanCSVData {
    fn get_req_headers(&self) -> HashMap<String, String> {
        let input = &self.request_headers;
        let mut headers = HashMap::new();

        let mut start = 0;

        while let Some(colon) = input[start..].find(':') {
            let colon = start + colon;

            let key = input[start..colon].trim();

            let mut end = input.len();

            let mut pos = colon + 1;
            while let Some(next) = input[pos..].find("; ") {
                let next = pos + next + 2;

                if let Some(c) = input[next..].find(':') {
                    let candidate = &input[next..next + c];

                    if candidate
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                    {
                        end = next - 2;
                        break;
                    }
                }

                pos = next;
            }

            let value = input[colon + 1..end].trim();

            headers.insert(key.to_string(), value.to_string());

            if end == input.len() {
                break;
            }

            start = end + 2;
        }

        headers

    }
}

impl WarmDatasetFileReader for MsanCSVData {
    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmDatasetFileReaderHelper::parse_csv(file);
        let mut requests = Array1::<Request<String>>::default(samples.len());

        // For each sample create a Request and add it to `requests` array
        for (i, sample) in samples.iter().enumerate() {
            let mut req = Request::builder()
            .uri(format!("{}", sample.uri))
            .method(WarmDatasetFileReaderHelper::get_method(&sample.method).expect("Error getting parsing method"))
            .version(WarmDatasetFileReaderHelper::get_protocol_version(&sample.request_protocol).expect(format!("Error while parsing HTTP protocol {}", sample.request_protocol).as_str()));

            let headers = sample.get_req_headers();
            for key in headers.keys() {
                req = req.header(key, headers.get(key).expect("Should never happen"));
            }
            
            requests[i] = req
                .body(sample.request_body.clone())
                .expect(format!("Error while building request with URI {}. Can happen if URI is not valid.", sample.uri).as_str());
        }
        
        requests
    }
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct PayloadAllTheThingsReader{
    payload: String,
    label: String,
}

impl WarmDatasetFileReader for PayloadAllTheThingsReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        // Read csv file
        let samples: Vec<Self> = WarmDatasetFileReaderHelper::parse_csv(file);
        let mut requests = Array1::<Request<String>>::default(samples.len()*2);

        // Get requests from samples
        for (i, sample) in samples.iter().enumerate(){
            let mut payload = sample.payload.clone();

            // Create GET request
            let get_req = Request::builder()
            .uri(format!("/?p={payload}"))
            .version(http::Version::HTTP_11)
            .method(Method::GET)
            .body(String::new());

            // If an error is thrown while building the request try urlencoding the URI, then if it's still not working panic.
            let get_req = match get_req {
                Ok(v) => v,
                Err(_) => {
                    payload = urlencoding::encode(&payload).into_owned();

                    Request::builder()
                        .uri(format!("/?p={payload}"))
                        .version(http::Version::HTTP_11)
                        .method(Method::GET)
                        .body(String::new())
                        .expect("Error while building request")
                }
            };

            // Create POST request
            let post_req = Request::builder()
            .uri(format!("/test_post"))
            .version(http::Version::HTTP_11)
            .method(Method::POST)
            .body(payload)
            .expect("Error while building request");
    
            requests[i] = get_req;
            requests[i+1] = post_req;
        }

        requests
    }
}

#[derive(Debug, serde::Deserialize)]
// https://github.com/openappsec/waf-comparison-project/tree/main/Data
pub struct OpenappsecReader{
    method: String,
    url: String,
    headers: HashMap<String, String>,
    data: String,
}

impl WarmDatasetFileReader for OpenappsecReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmDatasetFileReaderHelper::parse_json(file);
        let mut requests = Array1::<Request<String>>::default(samples.len());

        for (i, sample) in samples.iter().enumerate(){
            let method = WarmDatasetFileReaderHelper::get_method(
                &sample.method,
            ) .expect("Error getting request method");

            let mut req = Request::builder()
                .uri(&sample.url)
                .version(http::Version::HTTP_11)
                .method(method);

            // Get request headers
            for (name, value) in &sample.headers {
                req = req.header(name, value);
            }

            let req = req.body(sample.data.clone()).unwrap();

            requests[i] = req;
        }

        requests
    }
}

#[allow(dead_code)]
pub fn get_modsec_engine_pl4() -> ModSecEngine {
    let engine = ModSecEngineBuilder::new()
    .with_config_file("data/setup/modsecurity.conf")
    .with_config_file("data/setup/crs-setup-pl4.conf")
    .with_rules_from_folder("data/crs") 
    .build();

    engine
}

#[allow(dead_code)]
pub fn get_modsec_engine_pl1() -> ModSecEngine {
    let engine = ModSecEngineBuilder::new()
    .with_config_file("data/setup/modsecurity.conf")
    .with_config_file("data/setup/crs-setup-pl1.conf")
    .with_rules_from_folder("data/crs")
    .build();

    engine
}

#[allow(dead_code)]
pub fn get_all_train_dataset() -> WarmMLDataset {
    WarmMLDataset::builder()
        .add_file_async::<MsanCSVData>("msan sqli", "data/ml_dataset/msan/SQLInjectionRequestsDataset.csv", true)
        .add_file_async::<MsanCSVData>("msan command injection", "data/ml_dataset/msan/CommandInjectionRequestsDataset.csv", true)
        .add_file_async::<PolyglotJsonReader>("polyglot misc malicious", "data/ml_dataset/polyglot/polygot_payloads.jsonl", true)
        .add_file_async::<HttpParamsDatasetReader>("misc malicious", "data/ml_dataset/http-params-dataset/malicious.json", true)
        .add_file_async::<PayloadAllTheThingsReader>("payload-all-the-things", "data/ml_dataset/payload-all-the-things/train.csv", true)
        .add_file_async::<HttpParamsDatasetReader>("misc legitimate", "data/ml_dataset/http-params-dataset/legitimate.json", false)
        .add_file_async::<MsanCSVData>("msan legitimate", "data/ml_dataset/msan/Legitimate1_train.csv", false)
        .add_file_async::<OpenappsecReader>("openappsec legitimate", "data/ml_dataset/openappsec/train.json", false)
        .build_async()

}

#[allow(dead_code)]
pub fn get_all_test_dataset() -> WarmMLDataset {
    WarmMLDataset::builder()
    .add_file_async::<PayloadAllTheThingsReader>("payload-all-the-things", "data/ml_dataset/payload-all-the-things/test.csv", true)
    .add_file_async::<WebPayloadsJsonReader>("web payloads malicious", "data/ml_dataset/web-payloads/web_payloads_test.jsonl", true)
    .add_file_async::<MsanCSVData>("msan sqli", "data/ml_dataset/msan/SQLInjectionRequestsDataset_test.csv", true)
    .add_file_async::<OpenappsecReader>("openappsec legitimate", "data/ml_dataset/openappsec/test.json", false)
    .add_file_async::<MsanCSVData>("msan legitimate", "data/ml_dataset/msan/Legitimate1_test.csv", false)
    .build_async()

}