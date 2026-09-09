use std::fs::File;
use http::{Method, Request};
use linfa::dataset::Pr;
use ndarray::{Array1};
use warm_ml::{WarmDatasetFileData, WarmDatasetFileReader, WarmMLModelParams, waf_engines::*};
use linfa_svm::SvmParams;
use std::io;

pub struct ModsecLearnReader;
impl WarmDatasetFileReader for ModsecLearnReader {
    fn get_data(id: String, file_path: &str) -> Result<WarmDatasetFileData, io::Error>{
        let file = File::open(file_path).expect(format!("Can't read file {file_path}").as_str());
        let samples: Vec<String> = serde_json::from_reader(file).expect(format!("Error while parsing data of file {file_path}").as_str());
        
        let mut requests = Array1::from_elem(samples.len(), Request::new(String::new()));

        for (i, sample) in samples.iter().enumerate() {
            requests[i] = Request::builder()
                .uri(format!("http://localhost/?{sample}"))
                .version(http::Version::HTTP_11)
                .method(Method::GET)
                .body(String::new())
                .expect(format!("Error while building request. Can happen if given sample {sample} is not url encoded").as_str());
        }

        Ok(WarmDatasetFileData::new(
            String::from(file_path),
            id,
            requests,
        ))
    }
}

fn main(){
    let engine = ModSecEngineBuilder::new()
            .with_rules_from_file("data/crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
            .with_rules_from_file("data/crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf")
            .build();

    println!("Creating dataset");
    let warm_model_dataset = warm_ml::WarmMLDataset::default()
        .add_train_json::<ModsecLearnReader>("data/ml_dataset/sqli/legitimate_train.json", false)
        .add_train_json::<ModsecLearnReader>("data/ml_dataset/sqli/malicious_train.json", true);

    let mut warm_model = warm_ml::WarmMLModel::default();
    let svm_params = SvmParams::<f64,Pr>::new().pos_neg_weights(0.5, 0.5);

    println!("Train phase");
    warm_model.train(&warm_model_dataset, &engine, WarmMLModelParams::Svm(svm_params));

    println!("Test phase");
    warm_model.test(&warm_model_dataset, &engine);

    println!("Saving the model");
    warm_model.save("data/model/warm_example.bin")
}