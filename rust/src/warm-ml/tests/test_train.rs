use linfa::dataset::Pr;
use warm_ml::{WarmMLDataset, WarmMLModelAlgorithm, WarmMLModelAlgorithmParseError, WarmMLModelParams, waf_engines::WafEngine};
use linfa_svm::SvmParams;
use std::{sync::OnceLock, time::Instant};

mod common;

const SEED: u64 = 15;
static TRAIN_DATASET: OnceLock<WarmMLDataset>= OnceLock::new();


fn train_modsec_random(model_file: String, algorithm: WarmMLModelAlgorithm, usage_percentage: f32, legit_percentage: f32, seed: u64){
    let engine = common::get_modsec_engine_pl4();

    println!("Creating dataset for {model_file}");
    let warm_model_dataset = TRAIN_DATASET.get_or_init(common::get_all_train_dataset);

    println!("Reducing dataset for {model_file} from an initial size of {}", warm_model_dataset.get_samples_len());
    let warm_model_dataset = warm_model_dataset.select_samples(usage_percentage, legit_percentage, seed);
    println!("Dataset size after reduction with {usage_percentage}% usage: {}", warm_model_dataset.get_samples_len()); 
    
    let mut warm_model = warm_ml::WarmMLModel::default();

    println!("Training {model_file}");
    let now = Instant::now();
    match algorithm {
        WarmMLModelAlgorithm::LogisticRegression => {
            warm_model.train(&warm_model_dataset, &engine, WarmMLModelParams::LogisticRegression);
        },
        WarmMLModelAlgorithm::Svm => {
            let svm_params = SvmParams::<f32,Pr>::new().pos_neg_weights(1.0,1.0).linear_kernel();
            warm_model.train(&warm_model_dataset, &engine, WarmMLModelParams::Svm(svm_params));
        }
    }
    println!("Elapsed time for training {model_file} with {} features and {} samples: {}s", 
                engine.get_num_rules(), 
                warm_model_dataset.get_samples().len(),
                now.elapsed().as_millis() as f64 / 1000.0);

    println!("Saving {model_file}");
    warm_model.save(model_file.as_str());
}

macro_rules! generate_partial_train_tests {
    ($($name:ident => $alg_str:expr, $usage_percentage:expr, $legit_percentage:expr),*) => {
        $(
            #[test]
            fn $name() {
                let algorithm: Result<WarmMLModelAlgorithm, WarmMLModelAlgorithmParseError> = $alg_str.parse();
                if let Ok(algorithm) = algorithm{
                    train_modsec_random(format!("data/model/warm_{}_{}_{}.bin", $alg_str, $usage_percentage, $legit_percentage), algorithm, $usage_percentage, $legit_percentage, SEED)
                } else {
                    println!("Spiecifed wrong algorithm in test name!");
                }
            }
        )*
    };
}

generate_partial_train_tests!(
    train_svm_010_050 => "svm", 10.0, 50.0,
    train_svm_030_050 => "svm", 30.0, 50.0,
    train_svm_050_050 => "svm", 50.0, 50.0,
    train_svm_010_070 => "svm", 10.0, 70.0,
    train_lr_010_050 => "lr",10.0, 50.0,
    train_lr_010_010 => "lr",10.0, 10.0,
    train_lr_030_050 => "lr",30.0, 50.0,
    train_lr_050_050 => "lr",50.0, 50.0,
    train_lr_050_070 => "lr",50.0, 70.0,
    train_lr_070_050 => "lr",70.0, 50.0,
    train_lr_100_050 => "lr",100.0, 50.0,
    train_lr_100_080 => "lr",100.0, 80.0,
    train_lr_100_020 => "lr",100.0, 20.0, 
    train_lr_100_010 => "lr",100.0, 10.0
);