use http::Request;
use ndarray::{Array1, array};
use warm_ml::waf_engines::*;
use warm_ml::*;

fn train() {
    let engine = MockEngine::default();

    let malicious_requests: Array1<Request<String>> = array![
        urlencoding::encode("a=<script>alert</script>"),
        urlencoding::encode("a=/admin/"),
        urlencoding::encode("a=admin"),
    ].iter().map(|payload| {
        Request::builder().uri(format!("/?{payload}")).body(String::new()).expect("Error building request")
    }).collect();

    let legit_requests: Array1<Request<String>> = array![
        urlencoding::encode("a=onoanof"),
        urlencoding::encode("a=something"),
        urlencoding::encode("a=nonoan"),
    ].iter().map(|payload| {
        Request::builder().uri(format!("/?{payload}")).body(String::new()).expect("Error building request")
    }).collect();

    let dataset = WarmMLDataset::default()
                        .add_train_plain("mock legit requests", legit_requests, false)
                        .add_train_plain("mock malicious requests", malicious_requests, true);
                    
    let mut warm_model = WarmMLModel::default();

    warm_model.train(&dataset, &engine, WarmMLModelParams::LogisticRegression);
    warm_model.test(&dataset, &engine);
    warm_model.save("data/model/warm_mock.bin");
}

fn test() {
    let engine = MockEngine::default();
    let warm = Warm::load(
        "data/model/warm_mock.bin", 
        engine, 
        WarmMLModelAlgorithm::LogisticRegression
    ).expect("Model file not found");

    let req = Request::builder().uri("/t?a=admin").body(String::new()).expect("Error while creating request");
    let verdict = warm.evaluate(&req);

    if verdict.is_safe() {
        println!("Request {} is safe", req.uri().to_string());
    } else {
        println!("Request is NOT safe");
    }
}

fn main() {
    train();
    test();
}