use ndarray::array;
use warm_ml::{dataset::*, ml_model::*, warm::*, waf_engines::*, warm_test::*};
use std::{str::FromStr, sync::OnceLock};
use urlencoding::encode;
use http::{Request,Uri};
use std::time::Instant;

mod common;
use crate::common::get_modsec_engine_pl4;

static TEST_DATASET: OnceLock<WarmDatasetBuilder>= OnceLock::new();
const RESULTS_FILES_PATH: &str = "data/results";
const MODELS_FILES_PATH: &str = "data/models";
const FEATURES_FILES_PATH: &str = "data/features";

fn create_request(payload: &str) -> Request<String> {
    let query = encode(payload);
    let uri = Uri::from_str(format!("http://localhost/?t={query}").as_str()).expect("Error while parsing uri");

    Request::builder()
        .uri(uri)
        .method("GET")
        .header("host", "example.com")
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

#[test]
fn test_req_get_post() {
    let payloads = array![
        "%f0%80%80%ae%f0%80%80%ae%c1%1cboot.ini",
        "..../0x5c..../0x5c..../0x5c..../0x5c..../0x5cwindows0x5csystem320x5cdrivers0x5cetc0x5chosts",
        "%3Cbdo%20oncopy%3D%22confirm%281%29%22%20contenteditable%3Etest%3C/bdo%3E",
        "%3Cbr%20onkeyup%3D%22prompt%281%29%22%20contenteditable%3Etest%3C/br%3E",
        "p=%3Cheader%20onclick%3D%22alert%281%29%22%3Etest%3C/header%3E",
        "%3Cheader%20onclick%3D%22alert%281%29%22%3Etest%3C/header%3E",
        "%2e%2e%uEFC8%2e%2e%uEFC8%2e%2e%uEFC8%2e%2e%uEFC8etc%uEFC8passwd",
        ";%20ls%20-l%20/tmp",
        "%22%3Ca%20href=%22%22...%22%22%20target=%22%22_blank%22%22%20rel=%22%22%22%22%3E%22",
        "%22%3C!--#echo%20var=%22%22DOCUMENT_URI%22%22%20--%3E%22",
        "http:www.whitelisteddomain.tld@0xd8.0x3a.0xd6.0xce",
        "xxe.dtd",
        ".php%5Cx00.png",
        "$user_info%20=%20get_user_info($user_id);",
        "%7B%20$ne:%201%20%7D"
    ];

    let waf = get_modsec_engine_pl4();

    for payload in payloads {
        let get_req = Request::builder().uri(format!("/?p={payload}")).method("GET").body(String::new()).unwrap();
        let post_req = Request::builder().uri(format!("/")).method("GET").body(String::from(payload)).unwrap();
        let get_post_req = Request::builder().uri(format!("/?p={payload}")).method("GET").body(String::from(payload)).unwrap();
        
        println!("Payload '{payload}:");
        let rules = waf.evaluate_rules(&get_req);
        println!("\tGET: {:?}", rules.iter().map(|r| r.get_id()).collect::<Vec<i64>>());

        let rules = waf.evaluate_rules(&post_req);
        println!("\tPOST: {:?}", rules.iter().map(|r| r.get_id()).collect::<Vec<i64>>());

        let rules = waf.evaluate_rules(&get_post_req);
        println!("\tGET_POST: {:?}", rules.iter().map(|r| r.get_id()).collect::<Vec<i64>>());
    }


}

fn test_warm_lr(model_name: &str) -> WarmDatasetTest {
    println!("Creating test dataset");
    let test_dataset = TEST_DATASET.get_or_init(common::get_all_test_dataset);
    
    let model_file_path = format!("{MODELS_FILES_PATH}/{model_name}.bin");
    let results_file_path = format!("{RESULTS_FILES_PATH}/{model_name}");


    let warm = Warm::<ModSecEngine, WarmModelLR>::load(
            &model_file_path, 
            common::get_modsec_engine_pl4()
    ).expect("File not found");
    //warm.set_threshold(Pr::new(0.80));

    let waf_engine = warm.get_waf_engine();

    println!("Performing tests for model {model_file_path}");

    let mut test_files: Vec<WarmFileTest> = Vec::new();

    for file in test_dataset.get_files() {
        let feature_dataset = WarmFeatureDataset::load(format!("{FEATURES_FILES_PATH}/{}.bin", file.get_normalized_name()).as_str());

        // Check if loading was successful. If not extract features and save them in a file.
        let feature_dataset = match feature_dataset {
            Ok(v) => {
                println!("Loaded feature dataset");
                v
            },
            Err(_) => {
                println!("Creating feature dataset");
                let loaded_dataset = WarmFeaturesExtractor::get_features_from_dataset(waf_engine, &test_dataset.build());
                loaded_dataset.save(format!("{FEATURES_FILES_PATH}/dataset.bin").as_str());
                loaded_dataset
            }
        };

        let test_file = WarmFileTest::test_with_feature_dataset(file.get_normalized_name(), &warm, &feature_dataset);
        test_files.push(test_file);
    }

    WarmDatasetTest::from_files_test(model_name.to_string(), test_files)
}

macro_rules! generate_lr_dataset_tests {
    ($($name:ident => $usage_percentage:expr, $legit_percentage:expr),*) => {
        $(
            #[test]
            fn $name() {
                let name = format!("warm_lr_{}_{}", $usage_percentage, $legit_percentage);
                let test_result = test_warm_lr(&name);
                    
                test_result.save_as_markdown(format!("{RESULTS_FILES_PATH}/{name}").as_str());
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

                let engine = ModSecEngineBuilder::new()
                    .with_config_file("data/setup/modsecurity.conf")
                    .with_config_file(configs_path[$pl_level-1])
                    .with_rules_from_folder("data/crs").build();

                let dataset = TEST_DATASET.get_or_init(common::get_all_test_dataset);
                let dataset = dataset.build();

                let test_name = format!("vanilla_pl{}", $pl_level);

                let test_result = WarmDatasetTest::test(test_name.to_string(), &engine, &dataset);

                test_result.save_as_markdown(format!("{RESULTS_FILES_PATH}/{test_name}").as_str());
            }
        )*
    };
}

generate_lr_dataset_tests!(
    dataset_lr_010_050 => 10.0, 50.0,
    dataset_lr_010_030 => 10.0, 30.0,
    dataset_lr_010_070 => 10.0, 70.0,

    dataset_lr_030_050 => 30.0, 50.0,

    dataset_lr_050_050 => 50.0, 50.0,

    dataset_lr_070_050 => 70.0, 50.0,
    
    // dataset_lr_100_090 => 100.0, 90.0,
    // dataset_lr_100_080 => 100.0, 80.0,
    dataset_lr_100_070 => 100.0, 70.0, 
    dataset_lr_100_060 => 100.0, 60.0,
    dataset_lr_100_050 => 100.0, 50.0,
    dataset_lr_100_040 => 100.0, 40.0,
    dataset_lr_100_030 => 100.0, 30.0
    // dataset_lr_100_020 => 100.0, 20.0, 
    // dataset_lr_100_010 => 100.0, 10.0
);

generate_vanilla_tests!(
    dataset_vanilla_1 => 1,
    dataset_vanilla_2 => 2,
    dataset_vanilla_3 => 3,
    dataset_vanilla_4 => 4
);