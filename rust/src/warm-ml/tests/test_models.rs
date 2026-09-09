use warm_ml::{WarmMLModelAlgorithm::{self}, waf_engines::{ModSecEngineBuilder, WafEngine}};
use std::{str::FromStr, sync::OnceLock};
use urlencoding::encode;
use http::{Request,Uri};
use warm_ml::*;
use std::time::Instant;
use std::fs;

mod common;

static TEST_DATASET: OnceLock<WarmMLDataset>= OnceLock::new();

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

fn create_request_xss() -> Request<String>{
    return create_request("<img onload=alert(\"test\")>")
}

fn create_request_sqli() -> Request<String>{
    return create_request("' select 1 -- -")
}

fn create_request_legitimate() -> Request<String> {
    return create_request("testing a LEGITimate request with &some $\' w\"eird haacter?! SELECT ");
}

fn test_modsec_with_mock(algorithm: WarmMLModelAlgorithm, version: &str, malicious_req: Request<String>){
    let model_alg = algorithm.to_string();

    let warm = Warm::<waf_engines::ModSecEngine>::load(
        format!("data/model/warm_{model_alg}_{version}.bin").as_str(), 
        common::get_modsec_engine_pl4(), 
        algorithm
    ).expect("File not found");

    let verdict = warm.evaluate(&malicious_req);
    println!("warm_{model_alg}_{version} scored {} for request {}", verdict.get_score().abs(), malicious_req.uri().to_string());
    assert!(!verdict.is_safe());

    let legitimate_req = create_request_legitimate();
    let verdict = warm.evaluate(&legitimate_req);
    println!("warm_{model_alg}_{version} scored {} for request {}", verdict.get_score().abs(), legitimate_req.uri().to_string());
    assert!(verdict.is_safe());
}

fn test_modsec_with_dataset(model_file_path: &str, algorithm: WarmMLModelAlgorithm) -> (Vec<(String, u32, u32)>, f32) {
    println!("Creating test dataset");
    let test_dataset = TEST_DATASET.get_or_init(common::get_all_test_dataset);
    let test_data = test_dataset.get_files_samples();

    let warm = Warm::<waf_engines::ModSecEngine>::load(
            model_file_path, 
            common::get_modsec_engine_pl4(), 
            algorithm
    ).expect("File not found");


    let mut average_time = 0.0;
    let mut results: Vec<(String, u32, u32)> = Vec::new();

    println!("Performing tests for model {model_file_path}");

    for data in test_data {
        let samples = data.0.get_samples();
        let mut id = data.0.get_id();
        let label = data.1;
        let mut correct_answers = 0;
        let mut wrong_answers = 0;

        if id.is_empty() {
            id = data.0.get_file_path();
        }

        for req in samples{
            let now = Instant::now();
            let verdict = warm.evaluate(req);
            average_time += now.elapsed().as_nanos() as f32;

            if verdict.is_safe() != label {
                correct_answers += 1;
            } else {
                wrong_answers += 1;
            }
        }

        results.push((String::from(id), correct_answers, wrong_answers));
    }

    average_time = (average_time / test_dataset.get_samples_len() as f32) / 1000000.0;  //Calculating the average and converting nano to milliseconds

    (results, average_time)
}

macro_rules! generate_dataset_tests {
    ($($name:ident => $alg_str:expr, $usage_percentage:expr, $legit_percentage:expr),*) => {
        $(
            #[test]
            fn $name() {
                let algorithm: Result<WarmMLModelAlgorithm, WarmMLModelAlgorithmParseError> = $alg_str.parse();

                if let Ok(algorithm) = algorithm{
                    let mut results_string: String;
                    
                    // Get results
                    let (results, avg_time) = test_modsec_with_dataset(format!("data/model/warm_{}_{}_{}.bin", $alg_str, $usage_percentage, $legit_percentage).as_str(), algorithm);

                    results_string = format!("Average elapsed time for evaluating {}_{}_{} model: {avg_time} ms", $alg_str, $usage_percentage, $legit_percentage);
                    results_string = format!("{results_string}\nTest results for {}_{}_{} model:", $alg_str, $usage_percentage, $legit_percentage);
                    
                    for result in results {
                        let (id, correct, wrong) = result;
                        let (id, correct, wrong) = (id, correct as f32, wrong as f32);

                        let correct_percentage = correct*100.0/(correct+wrong);

                        results_string = format!("{results_string}\n - Dataset \"{id}\": {correct_percentage}% ({correct} correct / {} total)", correct+wrong);
                    }

                    println!("{results_string}");
                    fs::write(format!("data/results/warm_{}_{}_{}.txt", $alg_str, $usage_percentage, $legit_percentage), results_string).expect("Error writing results to file");
                } else {
                    println!("Specified wrong algorithm in test name!");
                }


            }
        )*
    };
}

macro_rules! generate_mock_tests {
    ($($name:ident => $alg_str:expr, $version:expr, $request:expr),*) => {
        $(
            #[test]
            fn $name() {
                let algorithm: Result<WarmMLModelAlgorithm, WarmMLModelAlgorithmParseError> = $alg_str.parse();
                let version_str = match $version {
                    Some(n) => n.to_string(),
                    None => String::from("complete"),
                };

                if let Ok(algorithm) = algorithm{
                    test_modsec_with_mock(algorithm, version_str.as_str(), $request);
                }
            }
        )*
    };
}

macro_rules! generate_vanilla_tests {
    ($($name:ident => $pl_level:expr),*) => {
        $(
            #[test]
            fn $name() {
                let configs_path = vec![
                    "data/setup/crs-setup-pl1.conf",
                    "data/setup/crs-setup-pl2.conf",
                    "data/setup/crs-setup-pl3.conf",
                    "data/setup/crs-setup-pl4.conf",
                ];

                let mut results_string = String::from(format!("Test results for vanilla evaluation with pl {}:", $pl_level));

                let engine = ModSecEngineBuilder::new()
                    .with_config_file("data/setup/modsecurity.conf")
                    .with_config_file(configs_path[$pl_level-1])
                    .with_rules_from_folder("data/crs").build();
                println!("Creating test dataset");
                let dataset = TEST_DATASET.get_or_init(common::get_all_test_dataset);
                let data = dataset.get_files_samples();
                let mut average_time = 0.0;
                
                println!("Performing evaluations");
                // Loop through each file data
                for (file_data, label) in data{
                    let samples = file_data.get_samples();
                    let (mut correct, mut wrong) = (0.0,0.0);
                    
                    // Loop through each sample in file data
                    for sample in samples{
                        let now = Instant::now();
                        let result = engine.should_block(sample);
                        average_time += now.elapsed().as_nanos() as f64;

                        if result == *label {
                            correct += 1.0;
                        } else {
                            wrong += 1.0;
                        }

                    }

                    let correct_percentage = correct*100.0/(correct+wrong);
                    results_string = format!("{results_string}\n - Dataset \"{}\": {correct_percentage}% ({correct} correct / {} total)", file_data.get_id(), correct+wrong);
                }

                average_time = (average_time / dataset.get_samples_len() as f64) / 1000000.0;  //Calculating the average and converting nano to milliseconds
                results_string = format!("{results_string}\nAverage elapsed time for evaluation: {average_time} ms");

                fs::write(format!("data/results/vanilla_pl{}.txt", $pl_level), results_string).expect("Error writing results to file");

            }
        )*
    };
}

generate_dataset_tests!(
    dataset_svm_010_050 => "svm", 10.0, 50.0,
    dataset_svm_030_050 => "svm", 30.0, 50.0,
    dataset_svm_050_050 => "svm", 50.0, 50.0,
    dataset_svm_010_070 => "svm", 10.0, 70.0,
    dataset_lr_010_050 => "lr",10.0, 50.0,
    dataset_lr_010_010 => "lr",10.0, 10.0,
    dataset_lr_030_050 => "lr",30.0, 50.0,
    dataset_lr_050_050 => "lr",50.0, 50.0,
    dataset_lr_050_070 => "lr",50.0, 70.0,
    dataset_lr_070_050 => "lr",70.0, 50.0,
    dataset_lr_100_050 => "lr",100.0, 50.0,
    dataset_lr_100_080 => "lr",100.0, 80.0,
    dataset_lr_100_020 => "lr",100.0, 20.0, 
    dataset_lr_100_010 => "lr",100.0, 10.0
);

// generate_mock_tests!(
//     mock_sqli_svm_0100 => "svm", 100, create_request_sqli(),
//     mock_sqli_svm_1000 => "svm",1000, create_request_sqli(),
//     mock_sqli_svm_3000 => "svm",3000, create_request_sqli(),
//     mock_sqli_svm_complete => "svm",None::<usize>, create_request_sqli(),
//     mock_sqli_lr_0100 => "lr",100, create_request_sqli(),
//     mock_sqli_lr_1000 => "lr",1000, create_request_sqli(),
//     mock_sqli_lr_3000 => "lr",3000, create_request_sqli(),
//     mock_sqli_lr_8000 => "lr",8000, create_request_sqli(),
//     mock_sqli_lr_complete => "lr",None::<usize>, create_request_sqli(),

//     mock_xss_svm_0100 => "svm", 100, create_request_xss(),
//     mock_xss_svm_1000 => "svm",1000, create_request_xss(),
//     mock_xss_svm_3000 => "svm",3000, create_request_xss(),
//     mock_xss_svm_complete => "svm",None::<usize>, create_request_xss(),
//     mock_xss_lr_0100 => "lr",100, create_request_xss(),
//     mock_xss_lr_1000 => "lr",1000, create_request_xss(),
//     mock_xss_lr_3000 => "lr",3000, create_request_xss(),
//     mock_xss_lr_8000 => "lr",8000, create_request_xss(),
//     mock_xss_lr_complete => "lr",None::<usize>, create_request_xss()
// );

generate_vanilla_tests!(
    dataset_vanilla_1 => 1,
    dataset_vanilla_2 => 2,
    dataset_vanilla_3 => 3,
    dataset_vanilla_4 => 4
);