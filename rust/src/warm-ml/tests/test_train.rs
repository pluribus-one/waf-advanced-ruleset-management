use warm_ml::{dataset::*, ml_model::*, waf_engines::*};
use std::{sync::OnceLock, time::Instant};

mod common;

const SEED: u64 = 15;
static TRAIN_DATASET: OnceLock<WarmDatasetBuilder>= OnceLock::new();

fn train_warm_lr(model_name: String, usage_percentage: f32, legit_percentage: f32, seed: u64){
    let engine = common::get_modsec_engine_pl4();

    let dataset_builder = TRAIN_DATASET.get_or_init(common::get_all_train_dataset);
    println!("Building dataset for {model_name}");
    let dataset = dataset_builder.build_with(usage_percentage, legit_percentage, seed);
    
    println!("Extracting features for dataset with {usage_percentage}% usage and {legit_percentage}% legitimate");
    let feature_dataset = WarmFeaturesExtractor::get_features_from_dataset(&engine, &dataset);

    println!("Training model {model_name}");
    let now = Instant::now();

    let warm_model = WarmModelLR::train(&feature_dataset, WarmModelParamsLR)
        .set_inverted_probabilities(legit_percentage > 50.0);

    println!("Elapsed time for training {model_name} with {} features and {} samples: {}s", 
                engine.get_num_rules(), 
                dataset.get_samples_count(),
                now.elapsed().as_millis() as f64 / 1000.0);

    println!("Saving {model_name}");
    warm_model.save(format!("data/models/{}.bin", model_name).as_str());

    println!("Generating plot");
    warm_model.plot_lr_coefficients(&engine, format!("data/results/{}.png", model_name).as_str()).expect("Error while creating plot.");
}

macro_rules! generate_lr_train_tests {
    ($($name:ident => $usage_percentage:expr, $legit_percentage:expr),*) => {
        $(
            #[test]
            fn $name() {
                train_warm_lr(format!("warm_lr_{}_{}", $usage_percentage, $legit_percentage), $usage_percentage, $legit_percentage, SEED)
            }
        )*
    };
}

generate_lr_train_tests!(
    train_lr_010_050 => 10.0, 50.0,
    train_lr_010_030 => 10.0, 30.0,
    train_lr_010_070 => 10.0, 70.0,

    train_lr_030_050 => 30.0, 50.0,

    train_lr_050_050 => 50.0, 50.0,

    train_lr_070_050 => 70.0, 50.0,

    // train_lr_100_090 => 100.0, 90.0,
    // train_lr_100_080 => 100.0, 80.0,
    train_lr_100_070 => 100.0, 70.0, 
    train_lr_100_060 => 100.0, 60.0,
    train_lr_100_050 => 100.0, 50.0,
    train_lr_100_040 => 100.0, 40.0,
    train_lr_100_030 => 100.0, 30.0
    // train_lr_100_020 => 100.0, 20.0, 
    // train_lr_100_010 => 100.0, 10.0
);