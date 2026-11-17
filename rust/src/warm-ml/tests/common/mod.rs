use std::{collections::HashMap};
use ndarray::{Array1};
use warm_ml::{dataset::*, waf_engines::*, open_dataset_readers::*};
use http::{Method, Request, Version};


#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
// A fixed version of https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset
pub struct WebPayloadsJsonReader{
    id: String,
    description: String,
    payload: String,
    context: String,
    attack_type: String,
    severity: String,
}
impl WarmFileReader for WebPayloadsJsonReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmFileReaderCommons::parse_json(file);
        
        // Get requests array from samples
        let mut requests = Vec::<Request<String>>::with_capacity(samples.len()*2);

        for sample in samples {
            // Url encode the payload
            let payload = urlencoding::encode(&sample.payload).into_owned();

            // Create GET request
            let get_req = Request::builder()
            .uri(format!("/?p={payload}"))
            .version(http::Version::HTTP_11)
            .method(Method::GET)
            .header("Host", "example.com")
            .body(String::new())
            .expect("Error while building request. Can happen if given sample {payload} is not url encoded");

            // Create POST request
            let post_req = Request::builder()
            .uri(format!("/test_post"))
            .version(http::Version::HTTP_11)
            .method(Method::POST)
            .header("Host", "example.com")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", payload.len())
            .body(payload)
            .expect("Error while building request.");
    
            requests.push(get_req);
            requests.push(post_req);
        }

        Array1::from_vec(requests)
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

impl WarmFileReader for MsanCSVData {
    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmFileReaderCommons::parse_csv(file);
        let mut requests = Array1::<Request<String>>::default(samples.len());

        // For each sample create a Request and add it to `requests` array
        for (i, sample) in samples.iter().enumerate() {
            let mut req = Request::builder()
            .uri(format!("{}", sample.uri))
            .header("Host", "exaHostmple.com")
            .method(WarmFileReaderUtils::get_method(&sample.method).expect("Error getting parsing method"))
            .version(WarmFileReaderUtils::get_protocol_version(&sample.request_protocol).expect(format!("Error while parsing HTTP protocol {}", sample.request_protocol).as_str()));

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
pub fn get_all_train_dataset() -> WarmDatasetBuilder {
    println!("Creating train dataset");

    WarmDataset::builder()
        // non public datasets
        // .add_file::<MsanCSVData>("msan sqli train", "data/ml_dataset/closed/msan/sqli_train.csv", true)
        // .add_file::<MsanCSVData>("msan com inj train", "data/ml_dataset/closed/msan/ci_train.csv", true)
        // .add_file::<MsanCSVData>("msan legitimate train", "data/ml_dataset/closed/msan/legitimate_train.csv", false)
        // .add_file::<WebPayloadsJsonReader>("web payloads malicious train", "data/ml_dataset/closed/web-payloads/web_payloads_test.json", true)
        .add_file::<OpenappsecReader>("openappsec malicious train", "data/ml_dataset/open/openappsec/malicious_train.json", true)
        .add_file::<OpenappsecReader>("openappsec legitimate train", "data/ml_dataset/open/openappsec/legitimate_train.json", false)
        .add_file::<PolyglotJsonReader>("polyglot misc malicious train", "data/ml_dataset/open/polyglot/malicious_train.jsonl", true)
        .add_file::<PayloadAllTheThingsReader>("payload-all-the-things train", "data/ml_dataset/open/payload-all-the-things/malicious_train.csv", true)
        .add_file::<HttpParamsDatasetReader>("misc malicious train", "data/ml_dataset/open/http-params-dataset/malicious_train.csv", true)
        .add_file::<HttpParamsDatasetReader>("misc legitimate train", "data/ml_dataset/open/http-params-dataset/legitimate_train.csv", false)

}

#[allow(dead_code)]
pub fn get_all_test_dataset() -> WarmDatasetBuilder {
    println!("Creating test dataset");

    WarmDataset::builder()
    // non public datasets
    // .add_file::<MsanCSVData>("msan sqli test", "data/ml_dataset/closed/msan/sqli_test.csv", true)
    // .add_file::<MsanCSVData>("msan legitimate test", "data/ml_dataset/closed/msan/legitimate_test.csv", false)
    .add_file::<OpenappsecReader>("openappsec malicious test", "data/ml_dataset/open/openappsec/malicious_test.json", true)
    .add_file::<OpenappsecReader>("openappsec legitimate test", "data/ml_dataset/open/openappsec/legitimate_test.json", false)
    .add_file::<PayloadAllTheThingsReader>("payload-all-the-things test", "data/ml_dataset/open/payload-all-the-things/malicious_test.csv", true)
    .add_file::<HttpParamsDatasetReader>("http params malicious test", "data/ml_dataset/open/http-params-dataset/malicious_test.csv", true)
    .add_file::<HttpParamsDatasetReader>("http params legitimate test", "data/ml_dataset/open/http-params-dataset/legitimate_test.csv", false)
}