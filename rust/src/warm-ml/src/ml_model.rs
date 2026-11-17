use crate::{dataset::*, waf_engines::WafEngine};
use linfa::{Dataset, dataset::Pr, traits::{Fit}};
use linfa_logistic::{FittedLogisticRegression, LogisticRegression};
use ndarray::{Array1, Array2, ArrayView2, };
use plotters::{backend::BitMapBackend, chart::ChartBuilder, drawing::IntoDrawingArea, element::Rectangle, style::{Color, GREEN, RED, WHITE}};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs::{self}, io::{self}};
use http::Request;

/// A struct used for extracting features
pub struct WarmFeaturesExtractor{}
impl WarmFeaturesExtractor {
    /// Extract features from a [`Request<String>`].
    /// 
    /// # Arguments
    /// * `waf_engine` - A [WafEngine] implementation used for extracting features
    /// * `request` - A [`Request<String>`] to be extracted
    /// 
    /// # Returns
    /// - [Ok] with an [Array1<f32>] with the extracted features.
    /// - [Err] when an unknown rule is triggered. The [Err] contains the id of that rule.
    pub fn get_features_from_request<T: WafEngine>(waf_engine: &T, request: &Request<String>) -> Result<Array1<f32>, i64>{
        let mut features = Array1::<f32>::zeros(waf_engine.get_num_rules());
        let triggered_rules = waf_engine.evaluate_rules(request);

        // For each rule get its id and if not found return error
        for rule in triggered_rules {
            let rule_id = rule.get_id();
            let index = waf_engine.get_rule_index(rule_id);

            if let Some(index) = index {
                features[*index] = 1.0;
            } else {
                return Err(rule_id)
            }
        }

        Ok(features)
    }

    /// Extract features from a [`WarmDatasetFile`].
    /// 
    /// # Arguments
    /// * `waf_engine` - A [WafEngine] implementation used for extracting features
    /// * `file` - A [`WarmDatasetFile`] to be extracted
    /// 
    /// # Returns
    /// A [`WarmFeatureDataset`] containing all extracted features
    pub fn get_features_from_file<T: WafEngine>(waf_engine: &T, file: &WarmDatasetFile) -> WarmFeatureDataset{
        let mut features_list: Array2<f32> = Array2::<f32>::zeros((file.get_samples_count(), waf_engine.get_num_rules()));
        let mut label_list: Array1<bool> = Array1::<bool>::from_elem(file.get_samples_count(), false);

        let mut skipped_samples_counter = 0;
        let mut next_sample_index = 0;

        let samples = file.get_samples();
        for sample in samples {
            let result = WarmFeaturesExtractor::get_features_from_request(waf_engine, sample);

            match result {
                Ok(features) => {
                    features_list.row_mut(next_sample_index).assign(&features);
                    label_list[next_sample_index] = file.get_label();
                    next_sample_index += 1;
                },
                Err(_rule_id) => {
                    // Uncomment this line for debugging the warning
                    //println!("Triggered rule with id {_rule_id} for request:\n{:?}", sample);
                    skipped_samples_counter += 1;
                }
            }
        }

        if skipped_samples_counter > 0 {
            println!("WARNING: Skipped {skipped_samples_counter} samples from file {}. If this number is high could be a problem.", file.get_name())
        }

        WarmFeatureDataset { features_list, label_list }
    }

    /// Extract features from a [`WarmDataset`].
    /// 
    /// # Arguments
    /// * `waf_engine` - A [WafEngine] implementation used for extracting features
    /// * `dataset` - A [`WarmDataset`] to be extracted
    /// 
    /// # Returns
    /// A [`WarmFeatureDataset`] containing all extracted features
    pub fn get_features_from_dataset<T: WafEngine>(waf_engine: &T, dataset: &WarmDataset) -> WarmFeatureDataset{
        let mut features_list: Array2<f32> = Array2::<f32>::zeros((dataset.get_samples_count(), waf_engine.get_num_rules()));
        let mut label_list: Array1<bool> = Array1::<bool>::from_elem(dataset.get_samples_count(), false);

        let mut next_feature_row = 0;

        let files = dataset.get_files();
        for file in files {
            let file_features_list = WarmFeaturesExtractor::get_features_from_file(waf_engine, file);
            
            // Copy each features row in `features_list`
            for row in file_features_list.features_list.rows(){
                features_list.row_mut(next_feature_row).assign(&row);
                label_list[next_feature_row] = file.get_label();
                next_feature_row += 1;
            }
        }

        WarmFeatureDataset { features_list, label_list }
    }
}

/// A struct used to represent a collection of features and its labels.
#[derive(Serialize, Deserialize)]
pub struct WarmFeatureDataset {
    features_list: Array2<f32>,
    label_list: Array1<bool>,
}

impl WarmFeatureDataset {
    pub fn get_features_list(&self) -> &Array2<f32> {
        &self.features_list
    }

    pub fn get_labels_list(&self) -> &Array1<bool> {
        &self.label_list
    }

    /// Returns this object as a tuple like: (features_list,label_list)
    pub fn as_tuple(&self) -> (&Array2<f32>, &Array1<bool>) {
        (&self.features_list, &self.label_list)
    }

    /// Saves this object into a file in the given `file_path`.
    /// 
    /// # Arguments
    /// * `file_path` - The complete file path where will be saved this object
    /// 
    /// # Crashes
    /// If there was an error writing the file or serializing the model
    pub fn save(&self, file_path: &str) {
        let result = bincode::serde::encode_to_vec(self, bincode::config::standard()).expect("An error occurred while encoding the model");
        fs::write(file_path, result).expect("An error occurred while saving the dataset");
    }

    /// Loads a [`WarmFeatureDataset`] from a file in the given `file_path`.
    /// 
    /// # Arguments
    /// * `file_path` - The complete file path of the file to load
    /// 
    /// # Returns
    /// - [Ok] if loaded correctly
    /// - [Err] if there was an error while reading the file
    /// 
    /// # Crashes
    /// When deserialization gives an error
    pub fn load(file_path: &str) -> Result<Self, io::Error>{
        let bytes = fs::read(file_path)?;

        let (model,_): (Self, usize) = bincode::serde::decode_from_slice(&bytes,bincode::config::standard())
                                                                .unwrap_or_else(|_| panic!("Error while loading the model from file {file_path}"));
        
        return Ok(model)
    }
}

/// A trait that represents generic machine learning algorithm parameters
pub trait WarmModelParams{}

/// A trait that represents a generic trained model.
pub trait WarmModel {
    type Params: WarmModelParams;

    /// Creates and trains a model with the given [`WarmFeatureDataset`] and parameters
    /// 
    /// # Arguments
    /// * `features_list` - A [`WarmFeatureDataset`] used to train the model
    /// * `ml_params` - A [`WarmModelParams`] implementation with parameters to use in the machine learning algorithm
    /// 
    /// # Returns
    /// A trained model 
    fn train(features_list: &WarmFeatureDataset, ml_params: Self::Params) -> Self;
    /// Predict probabilities of malicious requests given the features.
    /// 
    /// **Note:** The returned probabilities are inverted according to the result of [`Self::has_inverted_probabilities`] .
    /// 
    /// # Arguments
    /// * `features_list` - A [`ArrayView2<f32>`] with a list of features structured like:
    ///```
    /// [
    ///    [triggered_rule0, triggered_rule1, triggered_rule2, ...]
    ///    [triggered_rule0, triggered_rule1, triggered_rule2, ...]
    ///    ...
    /// ]
    /// ```
    /// 
    /// # Returns
    /// An [`Array1<Pr>`] with the predicted probabilities for each row of `features_list`.
    /// 
    /// **Normally** a probability near 1 signals a malicious request, otherwise a value near 0 signals a legitimate request.
    fn predict(&self, features_list: ArrayView2<f32>) -> Array1<Pr>;
    /// Tells if this model uses inverted probabilities
    fn has_inverted_probabilities(&self) -> bool; 
    /// Sets this model to use or not inverted probabilities. The default is `false`.
    /// 
    /// When probabilities are inverted a probability near 1 signals a legitimate request and near 0 a malicious request.
    fn set_inverted_probabilities(self, value: bool) -> Self;

    /// Saves model in a file.
    /// 
    /// # Arguments
    /// * `file_path` - The path where will be saved the model
    fn save(&self, file_path: &str);

    ///Loads a [`WarmModel`] from a file.
    /// # Arguments
    /// * `file_path` - The complete file path where the model is saved
    /// 
    /// # Returns
    /// - [Ok] when model is loaded correctly
    /// - [io::Error] when an error appeared while reading the file.
    fn load(file_path: &str) -> Result<Self, io::Error>
        where Self: Sized;
}

/// An implementation of a [`WarmModel`] trained with logistic regression algorithm
pub struct WarmModelParamsLR;
impl WarmModelParams for WarmModelParamsLR{}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct WarmModelLR {
    model: FittedLogisticRegression<f32, bool>,
    inverted_probabilities: bool,
}

impl Default for WarmModelLR {
    /// Returns a model trained with two values. Don't use this function for creating a [`WarmModelLR`]
    fn default() -> Self {
        let features = Array2::<f32>::default((2,2));
        let labels = Array1::<bool>::default(2);
        let dataset = Dataset::new(features,labels);

        Self { model: LogisticRegression::new().fit(&dataset).unwrap(), inverted_probabilities: Default::default() }
    }
}

impl WarmModel for WarmModelLR {
    type Params = WarmModelParamsLR;

    fn train(features_list: &WarmFeatureDataset, _: WarmModelParamsLR) -> Self {
        let labels = features_list.get_labels_list().to_owned();
        let features_list = features_list.get_features_list().to_owned();
        let train_dataset = Dataset::new(features_list, labels);

        let trained_model = LogisticRegression::new().fit(&train_dataset).unwrap();

        Self {
            model: trained_model,
            inverted_probabilities: false,
        }
    }

    fn predict(&self, features_list: ArrayView2<f32>) -> Array1<Pr> {
        self.model.predict_probabilities(&features_list).map(|p| {
            if self.inverted_probabilities {
                Pr::new( 1.0 - *p as f32)
            } else {
                Pr::new( *p as f32)
            }
        })
    }

    fn has_inverted_probabilities(&self) -> bool {
        self.inverted_probabilities
    }

    fn save(&self, file_path: &str){
        let result = bincode::serde::encode_to_vec(self, bincode::config::standard()).expect("An error occurred while encoding the model");

        fs::write(file_path, result).expect("An error occurred while saving the model");
    }

    fn load(file_path: &str) -> Result<Self, io::Error>{
        let bytes = fs::read(file_path)?;

        let (model,_): (Self, usize) = bincode::serde::decode_from_slice(&bytes,bincode::config::standard())
                                                                .expect(&format!("Error while loading the model from file {file_path}"));
        
        return Ok(model)
    }
    
    fn set_inverted_probabilities(mut self, value: bool) -> Self{
        self.inverted_probabilities = value;

        self
    }
}

impl WarmModelLR {
    /// Creates and saves a plot image with logistic regression weights.
    /// 
    /// # Arguments
    /// * `waf_engine` - The engine used for training the model
    /// * `output_file_path` - The file path where will be saved the generated plot image  
    /// 
    /// # Returns
    /// - [`Ok`] if no error happened
    /// - [`Err`] if something went wrong during plot generation
    pub fn plot_lr_coefficients<T: WafEngine>(&self, waf_engine: &T, output_file_path: &str) -> Result<(), Box<dyn Error>>{
        // Get features names (that are the rule ids)
        let features: Vec<String> = waf_engine.get_rules().iter().map(|rule| {
            rule.get_id().to_string()
        }).collect::<Vec<String>>();
        let weights = self.model.params();

        // Sort and take only the first values
        let mut data: Vec<(String, f32)> = features
            .into_iter()
            .zip(weights.iter().copied())
            .collect();

        data.sort_by(|a, b| {
            b.1.abs()
                .partial_cmp(&a.1.abs())
                .unwrap()
        });

        data.truncate(25);

        // Draw and save plot

        let root = BitMapBackend::new(output_file_path, (900, 900)).into_drawing_area();

        root.fill(&WHITE)?;

        let max = data
            .iter()
            .fold(0.0_f32, |a, (_, w)| a.max(w.abs()));

        let mut chart = ChartBuilder::on(&root)
            .caption("Logistic Regression Coefficients", ("sans-serif", 30))
            .margin(30)
            .x_label_area_size(40)
            .y_label_area_size(120)
            .build_cartesian_2d(-max * 1.2..max * 1.2, 0..data.len())?;

        chart
            .configure_mesh()
            .disable_mesh()
            .y_labels(data.len())
            .y_label_formatter(&|y| {
                data.get(*y)
                    .map(|(name, _)| name.clone())
                    .unwrap_or_default()
            })
            .label_style(("sans-serif", 20))
            .draw()?;

        for (i, (_, weight)) in data.iter().enumerate() {            
            let color = if *weight >= 0.0 {
                GREEN.filled()
            } else {
                RED.filled()
            };

            chart.draw_series(std::iter::once(Rectangle::new(
                [(0.0, i), (*weight, i + 1)],
                color,
            )))?;
        }

        root.present()?;

        Ok(())
    }
}
/* TODO

pub struct MLParamsSVM {
    params: SvmParams<f32, Pr>
}
impl WarmModelParams for MLParamsSVM{}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MLModelSVM {
    model: Svm<f32, Pr>,
    inverted_probabilities: bool,
}

impl WarmModel for MLModelSVM {
    type Params = MLParamsSVM;

    fn train(features_list: &WarmModelFeaturesList, ml_params: MLParamsSVM) -> Self {
        let labels = features_list.get_labels().to_owned();
        let features_list = features_list.get_features_list().to_owned();
        let train_dataset = Dataset::new(features_list, labels);

        let trained_model = ml_params.params.fit(&train_dataset).unwrap();

        Self {
            model: trained_model,
            inverted_probabilities: false,
        }
    }

    fn predict(&self, features_list: &WarmModelFeaturesList) -> Array1<Pr> {
        todo!()
    }

    fn has_inverted_probabilities(&self) -> bool {
        self.inverted_probabilities
    }
    
    fn set_inverted_probabilities(&mut self) {
        todo!()
    }
    
    fn save(&self, file: File) {
        todo!()
    }
    
    fn load(file: File) -> Result<Self, io::Error>
        where Self: Sized {
        todo!()
    }
}*/