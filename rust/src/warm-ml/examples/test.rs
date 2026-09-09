use std::{str::FromStr};

use linfa::dataset::Pr;
use urlencoding::encode;

use http::{Request,Uri};
use warm_ml::{waf_engines::{ModSecEngineBuilder}, *};

fn create_request(payload: &str) -> Request<String> {
    let query = encode(payload);
    let uri = Uri::from_str(format!("http://localhost/?t={query}").as_str()).expect("Error while parsing uri");

    Request::builder()
        .uri(uri)
        .method("GET")
        .header("host", "localhost")
        .header("user-agent", "my-rust-client/1.0")
        .header("accept", "*/*")
        .header("content-type", "application/json")
        .body(String::new())
        .expect("Couldn't build request")
}

fn create_request_sqli() -> Request<String>{
    return create_request("' select 1 -- -")
}

fn main(){
    let engine = ModSecEngineBuilder::new()
            .with_rules_from_file("data/crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
            .with_rules_from_file("data/crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf")
            .build();
    
    let mut warm = Warm::<waf_engines::ModSecEngine>::load("data/model/warm_example.bin", engine, WarmMLModelAlgorithm::Svm).expect("File not found");
    
    let req =  create_request_sqli();
    let uri_string = req.uri().to_string();

    println!("Testing payload {}", uri_string);

    warm.set_threshold(Pr::even());

    let verdict = warm.evaluate(&req);

    if verdict.is_safe() {
        println!("PASSED: Request with payload {} with {} score and {} threshold", uri_string, verdict.get_score().abs(), verdict.get_used_threshold().abs());
    } else {
        println!("BLOCKED: Request with payload {} with {} score and {} threshold", uri_string, verdict.get_score().abs(), verdict.get_used_threshold().abs());
    }
}