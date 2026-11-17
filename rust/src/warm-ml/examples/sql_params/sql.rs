/*
This example shows how to train and use a Warm model for an old application that still uses SQL queries in URI.  
*/

use std::fs;

use http::Request;
use ndarray::Array1;
use serde::Deserialize;
use warm_ml::{dataset::*, ml_model::*, open_dataset_readers::*, waf_engines::{self, ModSecEngine, ModSecEngineBuilder, WafEngine}, warm::Warm};

#[derive(Debug, Deserialize)]
struct SqlLegitimate {
	id: usize,
	host: String,
	path: String,
	url: String,
}

impl WarmFileReader for SqlLegitimate {
	fn get_data(file: std::fs::File) -> Array1<Request<String>> {
        let samples: Vec<Self> = WarmFileReaderCommons::parse_csv(file);

		let mut requests = Vec::<Request<String>>::with_capacity(samples.len());
		for sample in samples {
			let request = Request::builder()
				.uri(sample.url)
				.header("Host", sample.host)
				.method("GET")
            	.version(http::Version::HTTP_11)
				.body(String::new())
				.expect("Error building request");

			requests.push(request);
		}

		Array1::from_vec(requests)
	}
}

fn get_or_load_dataset(file_path: &str, waf_engine: &ModSecEngine, dataset: &WarmDataset) -> WarmFeatureDataset{
	match WarmFeatureDataset::load(file_path) {
		Ok(v) => v,
		Err(_) => {
			let dataset = WarmFeaturesExtractor::get_features_from_dataset(waf_engine, dataset);
			dataset.save(file_path);
			dataset
		}
	}
}

fn train_or_load_model(file_path: &str, waf_engine: ModSecEngine, features: &WarmFeatureDataset) -> Warm<ModSecEngine, WarmModelLR>{
	let file_exists = fs::exists(file_path).unwrap();

	if file_exists {
		Warm::load(file_path, waf_engine).expect("Should not happen")
	} else {
		let model: WarmModelLR = WarmModelLR::train(&features, WarmModelParamsLR);
		model.save(file_path);

		Warm::new(model, waf_engine)
	}
}

fn test_model(warm_model_path: &str, train_features: &WarmFeatureDataset, test_features: &WarmFeatureDataset){
	let waf_engine = get_waf_engine();

	let warm: Warm<ModSecEngine, WarmModelLR>  = train_or_load_model(warm_model_path, waf_engine, &train_features);
	let confusion_matrix = warm.test_dataset(&test_features);

	println!("Warm model results: {} accuracy ; {} f1 score ; {} precision ; {} recall"
	, confusion_matrix.accuracy(), confusion_matrix.f1_score(), confusion_matrix.precision(), confusion_matrix.recall());
}

fn get_waf_engine() -> ModSecEngine{
	ModSecEngineBuilder::new()
		.with_config_file("data/setup/modsecurity.conf")
		.with_config_file("data/setup/crs-setup-pl4.conf")
		.with_rules_from_folder("data/crs") 
		.build()
}

fn main() {
	let waf_engine = get_waf_engine();
	
	// Dataset with open data + domain specific requests (sintetics)
	let train_dataset = WarmDataset::builder()
        .add_file::<OpenappsecReader>("openappsec malicious train", "data/ml_dataset/open/openappsec/malicious_train.json", true)
        .add_file::<OpenappsecReader>("openappsec legitimate train", "data/ml_dataset/open/openappsec/legitimate_train.json", false)
        .add_file::<PolyglotJsonReader>("polyglot misc malicious train", "data/ml_dataset/open/polyglot/malicious_train.jsonl", true)
        .add_file::<PayloadAllTheThingsReader>("payload-all-the-things train", "data/ml_dataset/open/payload-all-the-things/malicious_train.csv", true)
        .add_file::<HttpParamsDatasetReader>("misc malicious train", "data/ml_dataset/open/http-params-dataset/malicious_train.csv", true)
        .add_file::<HttpParamsDatasetReader>("misc legitimate train", "data/ml_dataset/open/http-params-dataset/legitimate_train.csv", false)
        .add_file::<SqlLegitimate>("custom domain requests", "examples/sql_params/sql_legitimates_train.csv", false)
		.build_with(100.0, 50.0, 10);

	let test_dataset = WarmDataset::builder()
		.add_file::<OpenappsecReader>("openappsec malicious test", "data/ml_dataset/open/openappsec/malicious_test.json", true)
		.add_file::<OpenappsecReader>("openappsec legitimate test", "data/ml_dataset/open/openappsec/legitimate_test.json", false)
		.add_file::<PayloadAllTheThingsReader>("payload-all-the-things test", "data/ml_dataset/open/payload-all-the-things/malicious_test.csv", true)
		.add_file::<HttpParamsDatasetReader>("http params malicious test", "data/ml_dataset/open/http-params-dataset/malicious_test.csv", true)
		.add_file::<HttpParamsDatasetReader>("http params legitimate test", "data/ml_dataset/open/http-params-dataset/legitimate_test.csv", false)
		.add_file::<SqlLegitimate>("custom domain requests test", "examples/sql_params/sql_legitimates_test.csv", false)
    	.build();

	let train_features = get_or_load_dataset("examples/sql_params/dataset_train.bin", &waf_engine, &train_dataset);
	let test_features = get_or_load_dataset("examples/sql_params/dataset_test.bin", &waf_engine, &test_dataset);
	
	test_model("examples/sql_params/custom_model.bin", &train_features, &test_features);
	test_model("data/models/warm_lr_100_50.bin", &train_features, &test_features);
}