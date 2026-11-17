use std::{collections::HashMap};
use ndarray::{Array1};
use crate::{dataset::*};
use http::{Method, Request};

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
//https://github.com/Morzeux/HttpParamsDataset/raw/refs/heads/master/payload_full.csv
pub struct HttpParamsDatasetReader{
    payload: String,
    length: String,
    attack_type: String,
    label: String,
}
impl WarmFileReader for HttpParamsDatasetReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>> {
        let samples: Vec<Self> = WarmFileReaderCommons::parse_csv(file);
        
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
                .header("Host", "example.com")
                .method(Method::GET)
                .body(String::new())
                .expect(format!("Error while building request. Can happen if given sample {sample} is not url encoded").as_str());
        }
        
        requests
    }
}



#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
// https://huggingface.co/datasets/darkknight25/polyglot_paylods_datasets
pub struct PolyglotJsonReader{
    payload: String,
    r#type: String,
    description: String,
}

impl WarmFileReader for PolyglotJsonReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmFileReaderCommons::parse_jsonl(file);

        let mut requests = Vec::<Request<String>>::with_capacity(samples.len()*2);

        // For each sample create a Request and put it in `requests`
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
pub struct PayloadAllTheThingsReader{
    payload: String,
    label: String,
}

impl WarmFileReader for PayloadAllTheThingsReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        // Read csv file
        let samples: Vec<Self> = WarmFileReaderCommons::parse_csv(file);
        let mut requests = Vec::<Request<String>>::with_capacity(samples.len()*2);

        // Get requests from samples
        for sample in samples {
            let mut payload = sample.payload.clone();

            // Create GET request
            let get_req = Request::builder()
            .uri(format!("/?p={payload}"))
            .version(http::Version::HTTP_11)
            .header("Host", "example.com")
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
                        .header("Host", "example.com")
                        .body(String::new())
                        .expect("Error while building request")
                }
            };

            // Create POST request
            let post_req = Request::builder()
            .uri(format!("/test_post"))
            .version(http::Version::HTTP_11)
            .method(Method::POST)
            .header("Host", "example.com")
            .header("Content-Length", payload.len())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(payload)
            .expect("Error while building request");
    
            requests.push(get_req);
            requests.push(post_req);
        }

        Array1::from_vec(requests)
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

impl WarmFileReader for OpenappsecReader {

    fn get_data(file: std::fs::File) -> Array1<Request<String>>{
        let samples: Vec<Self> = WarmFileReaderCommons::parse_json(file);
        let mut requests = Array1::<Request<String>>::default(samples.len());

        for (i, sample) in samples.iter().enumerate(){
            let method = WarmFileReaderUtils::get_method(
                &sample.method,
            ) .expect("Error getting request method");

            let mut req = Request::builder()
                .uri(&sample.url)
                .header("Host", "example.com")
                .header("Accept", "*/*")
                .version(http::Version::HTTP_11)
                .method(&method);

            if method == http::Method::POST {
                req = req.header("Content-Length", sample.data.len());
            }

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