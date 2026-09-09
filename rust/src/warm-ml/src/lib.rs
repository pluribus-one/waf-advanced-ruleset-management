pub mod waf_engines;

use crate::waf_engines::{WafEngine};
use linfa::{Dataset, dataset::Pr, traits::{Fit, Predict}};
use linfa_logistic::{FittedLogisticRegression, LogisticRegression};
use linfa_svm::{Svm, SvmParams};
use ndarray::{Array1, Array2, Axis};
use rand::{rngs::StdRng, seq::{SliceRandom}, *};
use std::{fmt::{self, Debug}, fs::{self, File}, io::{self, Read}, str::FromStr, thread::{self, JoinHandle}};
use http::{Method, Request, Version};

/// The result of a Warm evaluation.
/// 
/// # Examples
/// For a malicious request
/// ```ignore
/// let threshold = 0.5;
/// let score = Pr::new(0.98);
/// let safe = score < threshold;
/// let verdict = WarmVerdict::new(safe, threshold, score);
/// assert_eq!(verdict.is_safe(), false)
/// ```
/// 
/// For a legitimate request
/// ```ignore
/// let threshold = 0.5;
/// let score = Pr::new(0.1);
/// let safe = score < threshold;
/// let verdict = WarmVerdict::new(safe, threshold, score);
/// assert_eq!(verdict.is_safe(), true)
/// ```
pub struct WarmVerdict {
    /// Tells if the evaluated request is safe or not based on the used `threshold`
    safe: bool,
    /// The used threshold for setting the `safe` parameter
    used_threshold: Pr,
    /// The probability that the evaluated request is legitimate or malicious.
    /// A high value signals a malicious request. A low value signals a legitimate request.
    score: Pr,
}

impl WarmVerdict {
    /// Creates new WarmVerdict.
    ///
    /// # Arguments
    /// * `safe`: bool - Sets the result as a safe request
    /// * `used_threshold` - The used threshold during the evaluation
    /// * `score` - The score given by the model
    pub fn new(safe: bool, used_threshold: Pr, score: Pr) -> Self{
        WarmVerdict {
            safe,
            used_threshold,
            score,
        }
    }

    /// Tells if the evaluated request is safe
    pub fn is_safe(&self) -> bool{
        self.safe
    }

    /// Gives the malicous probability of the evaluated request
    pub fn get_score(&self) -> Pr {
        self.score
    }

    /// Gives the threshold value used for telling the safety of the evaluated request
    pub fn get_used_threshold(&self) -> Pr {
        self.used_threshold
    }
}

/// A `Warm` object gives access to the API for using the ml model.
/// It is associated with a [`WafEngine`]
/// 
/// # Examples
/// The typical use should be with a trained model saved in a file:
/// ```ignore
/// let engine = ModSecEngineBuilder::new().with_rules_from_file("rule_file.conf");
/// let algorithm = WarmMLModelAlgorithm::Svm;
/// let warm = Warm::<waf_engines::ModSecEngine>::load(
///        "model_file.bin", 
///        engine, 
///        algorithm
///    ).expect("Model file not found");
/// let malicious_req = http::Request::builder()
///                     .uri("/malicious")
///                     .body(String::new())
///                     .expect("Couldn't build request");
/// 
/// let verdict = warm.evaluate(&malicious_req);
/// assert!(!verdict.is_safe());
/// ```
/// 
/// If using a runtime trained model:
/// ```ignore
/// let model = WarmMLModel::default();
/// //...
/// //Train the model. Check WarmMLModel doc.
/// //...
/// let engine = ModSecEngineBuilder::new().with_rules_from_file("rule_file.conf");
/// let warm = Warm::<waf_engines::ModSecEngine>::new(model, engine);
/// let malicious_req = http::Request::builder()
///                     .uri("/malicious")
///                     .body(String::new())
///                     .expect("Couldn't build request");
/// 
/// let verdict = warm.evaluate(&malicious_req);
/// assert!(!verdict.is_safe());
/// ```
pub struct Warm<T: WafEngine>{
    /// The ml model used for evaluating requests
    ml_model: WarmMLModel,
    /// The engine used by the model and used as default in case of an untrained model.
    waf_engine: T,
    /// If a request has a malicious probability greater than `threshold`, the verdict will be set as unsafe.
    threshold: Pr,
}

impl<T: WafEngine> Default for Warm<T> {
    /// Creates a Warm object with default values.
    /// 
    /// # Returns
    /// A Warm object with an untrained model and an even threshold.
    fn default() -> Self {
        Self { 
            ml_model: WarmMLModel::default(), 
            waf_engine: T::default(), 
            threshold: Pr::even()
        }
    }
}

impl<T: WafEngine> Warm<T>{
    /// Creates new Warm object with the given parameters.
    pub fn new(model: WarmMLModel, waf_engine: T) -> Self{
        Self {
            ml_model: model,
            waf_engine,
            ..Warm::default()
        }
    }

    /// Changes the warm object `threshold` used. 
    pub fn set_threshold(&mut self, threshold: Pr){
        self.threshold = threshold;
    }

    /// Evaluates the given request using the model.
    /// **NOTE**: If tries to use an untrained model will use the given engine and a warning will be printed out.
    /// 
    /// # Returns
    /// A [`WarmVerdict`] with the results. 
    pub fn evaluate(&self, req: &http::Request<String>) -> WarmVerdict {
        let model = &self.ml_model.trained_model;

        if let Some(model) = model {
            let features = self.ml_model.extract_features(req, &self.waf_engine);
            
            // If extraction is Ok then use it otherwise use the waf engine for evaluation and return the result
            match features {
                Err(v) => {
                    println!("WARNING: The model couldn't evaluate the request because it triggered an unknown rule with id {v}. Using the waf engine for evaluation.");
                    
                    let is_safe = !self.waf_engine.should_block(req);
                    return WarmVerdict::new(is_safe, self.threshold, Pr::default())
                },
                _ => {}
            }

            let features = features.expect("Should not happen since it's already checked");
            
            let scores = match model {
                WarmMLModelTrained::Svm(m) => m.predict(&features),
                WarmMLModelTrained::LogisticRegression(m) => m.predict_probabilities(&features).map(|p| {Pr::new(*p as f32)}),
            };

            // A score is inverted if a score of 1.0 is a safe request and 0.0 is malicious. 
            let is_inverted_score = match model {
                //WarmMLModelTrained::LogisticRegression(_) => true,
                _ => false,
            };
            let score = scores[0];

            if is_inverted_score {
                let threshold = Pr::new(1.0 - *self.threshold);
                WarmVerdict::new(score > threshold, self.threshold, score)
            } else {
                // A request is safe if score < threshold
                WarmVerdict::new(score < self.threshold, self.threshold, score)
            }

        } else {
            println!("WARNING: Trying to evaluate a request with an untrained model. Using the waf engine for evaluation.");
            let is_safe = !self.waf_engine.should_block(req);
            WarmVerdict::new(is_safe, self.threshold, Pr::default())
        }
    }

    /// Evaluates the given request using directly the specified [`WafEngine`].
    /// 
    /// # Returns
    /// A [`WarmVerdict`] with the results.
    pub fn evaluate_vanilla(&self, req: &http::Request<String>) -> WarmVerdict {
        let is_safe = !self.waf_engine.should_block(req);

        WarmVerdict::new(is_safe, self.threshold, Pr::default())
    }

    /// Loads a trained ml model from a file
    /// 
    /// # Arguments
    /// * `file_path` - The complete path to a model file
    /// * `waf_engine` - The [`WafEngine`] used by the ml model
    /// * `algorithm` - The [`WarmMLModelAlgorithm`] used by the ml model
    /// 
    /// # Returns
    /// A [`Warm`] object if the model is loaded successfully.
    /// An [`io::Error`] if the file in the given `file_path` is not found. 
    pub fn load(file_path: &str, waf_engine: T, algorithm: WarmMLModelAlgorithm) -> Result<Warm<T>, io::Error>{
        let model = WarmMLModel::load(file_path, algorithm)?;
        
        Ok(
            Warm { 
                ml_model: model, 
                waf_engine: waf_engine, 
                ..Warm::default()
            }
        )
    }
}

/// All supported ml algorithms by [`WarmMLModel`]
#[derive(Copy, Clone)]
pub enum WarmMLModelAlgorithm {
    Svm,
    LogisticRegression,
}

impl ToString for WarmMLModelAlgorithm{
    /// Returns the lowercase name for an algorithm
    fn to_string(&self) -> String {
        match self {
            WarmMLModelAlgorithm::Svm => String::from("svm"),
            WarmMLModelAlgorithm::LogisticRegression => String::from("lr"),
        }
    }
}

impl FromStr for WarmMLModelAlgorithm{
    type Err = WarmMLModelAlgorithmParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "svm" => Ok(WarmMLModelAlgorithm::Svm),
            "lr" => Ok(WarmMLModelAlgorithm::LogisticRegression),
            _ => Err(WarmMLModelAlgorithmParseError(s.to_string())),
        }
    }
}

impl fmt::Display for WarmMLModelAlgorithmParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid enum variant: {}", self.0)
    }
}

#[derive(Debug)]
pub struct WarmMLModelAlgorithmParseError(String);
impl std::error::Error for WarmMLModelAlgorithmParseError {}

/// The internal trained models of a [`WarmMLModel`] object
pub enum WarmMLModelTrained{
    Svm(Svm<f32, Pr>),
    LogisticRegression(FittedLogisticRegression<f32, bool>),
}

/// The params used to train an internal model of a [`WarmMLModel`] object
pub enum WarmMLModelParams{
    Svm(SvmParams<f32, Pr>),
    LogisticRegression,
}

/// Manages the actual ml model
/// 
/// # Examples
/// Training a [`WarmMLModel`]:
/// ```ignore
/// let engine = ModSecEngineBuilder::new().with_rules_from_file("rule_file.conf");
/// let warm_model_dataset = warm_ml::WarmMLDataset::default()
///     .add_train_json::<ModsecLearnReader>("data/ml_dataset/sqli/legitimate_train.json", false, first_n_values)
///     .add_test_json::<ModsecLearnReader>("data/ml_dataset/sqli/malicious_test.json", true, first_n_values);
/// 
/// let mut warm_model = warm_ml::WarmMLModel::default();
/// warm_model.train(&warm_model_dataset, &engine, WarmMLModelParams::LogisticRegression);
/// warm_model.test(&warm_model_dataset, &engine);
/// warm_model.save(model_file.as_str());
/// ```
pub struct WarmMLModel{
    trained_model: Option<WarmMLModelTrained>,
}

impl Default for WarmMLModel {
    /// Creates a [`WarmMLModel`] with an untrained model.
    fn default() -> Self {
        Self {
            trained_model: None,
        }
    }
}

impl WarmMLModel{
    /// Trains a model with `params` using the `waf_engine` for extracting features
    /// and using the given `dataset`.
    /// Sets `trained_model` with a [`WarmMLModelTrained`] object
    pub fn train<T: WafEngine>(&mut self, dataset: &WarmMLDataset, waf_engine: &T, params: WarmMLModelParams){
        let (features, labels) = self.get_features_and_labels(&dataset, waf_engine);
        let train_dataset = Dataset::new(features, labels);

        self.trained_model = match params {
            WarmMLModelParams::Svm(p) => {
                Some(
                    WarmMLModelTrained::Svm(
                        p.fit(&train_dataset).unwrap()
                    )
                )
            },
            WarmMLModelParams::LogisticRegression => {
                Some(
                    WarmMLModelTrained::LogisticRegression(
                        LogisticRegression::new().fit(&train_dataset).unwrap()
                    )
                )
            },
        }
    }

    /// Extract the features and labels arrays from the `dataset`. This function is only used for training the model.
    /// 
    /// # Arguments
    /// * `dataset` - The dataset source for features and labels
    /// * `waf_engine` - The engine to use for evaluating the `samples`
    /// 
    /// # Returns:
    /// In first position an [`Array2<f32>`] with this structure:
    /// [
    ///     [rule0, rule1, rule2, ...]
    ///     [rule0, rule1, rule2, ...],
    ///     ... for each sample
    /// ]
    /// Each rulei has a value of 1.0 if triggered and 0.0 if untriggered. 
    /// 
    /// In second position the labels array
    fn get_features_and_labels<T: WafEngine>(&self, dataset: &WarmMLDataset, waf_engine: &T) -> (Array2<f32>, Array1<bool>) {
        let n_samples = dataset.get_samples_len();
        let n_features = waf_engine.get_num_rules();
        
        // Final arrays
        let mut features_array: Array2<f32> = Array2::default((n_samples, n_features));
        let mut labels: Array1<bool> = Array1::default(n_samples);

        let file_samples = dataset.get_files_samples();
        let mut tot_samples_counter = 0;    //A counter used for updating the correct `features_array` row and its label

        //Loop through every file sample
        for (file_sample, label) in file_samples {
            let samples = file_sample.get_samples();
            let mut skipped_samples_counter = 0;

            for sample in samples {
                //Get triggered rules
                let triggered_rules = waf_engine.evaluate(&sample);

                let mut features_are_ok = true; //If true each triggered rule is recognized by the waf engine

                //Loop through every triggered_rule and add it in the features
                for rule in triggered_rules {
                    let rule_index = waf_engine.get_rule_index(rule.get_id());
                    if let Some(rule_index) = rule_index {
                        features_array[[tot_samples_counter, *rule_index]] = 1.0;
                    } else {
                        // If a rule is unrecognized remove this row from `features_array` and `labels`
                        features_are_ok = false;
                        features_array.remove_index(Axis(0), tot_samples_counter);
                        labels.remove_index(Axis(0), tot_samples_counter);
                        skipped_samples_counter += 1;
                        break;
                    }
                }

                // If every triggered rule was recognized then add the row 
                if features_are_ok {
                    labels[tot_samples_counter] = *label;
                    tot_samples_counter += 1;
                }
            }

            if skipped_samples_counter > 0 {
                println!("WARNING: Skipping {skipped_samples_counter} samples from dataset file with id: '{}'", file_sample.get_id())
            }
        }

        (features_array, labels)
    }

    /// Extract the features from a single request. This function is only used for training the model.
    /// 
    /// # Arguments
    /// * `sample` - The request which will be evaluated for building the features array
    /// * `waf_engine` - The engine to use for evaluating the `samples`
    /// 
    /// # Returns:
    /// If [Ok] an error an [`Array2<f32>`] with this structure:
    /// [
    ///     [rule0, rule1, rule2, ...]
    /// ]
    /// Each rulei has a value of 1.0 if triggered and 0.0 if untriggered. 
    /// 
    /// If [Err] the error contains the unrecognized rule id.
    fn extract_features<T: WafEngine>(&self, sample: &Request<String>, waf_engine: &T) -> Result<Array2<f32>, i64> {
        let num_feature = waf_engine.get_num_rules();
        let mut features: Array2<f32> = Array2::<f32>::zeros((1, num_feature));

        //Get the triggered rules
        let triggered_rules = waf_engine.evaluate(sample);

        //Loop through every triggered_rule and add it in the features array
        for rule in triggered_rules {
            let rule_index = waf_engine.get_rule_index(rule.get_id());
            if let Some(rule_index) = rule_index {
                features[[0, *rule_index as usize]] = 1.0;
            } else {
                return Err::<Array2<f32>, i64>(rule.get_id());
            }
        }

        Ok(features)
    }

    /// Saves the svm model in a file.
    /// **NOTE**: If called on an untrained model does nothing.
    /// # Arguments
    /// * `file_path` - The path where will be saved the model
    pub fn save(&self, file_path: &str){
        if let Some(model) = &self.trained_model {
            let result = match model {
                WarmMLModelTrained::Svm(m) => bincode::serde::encode_to_vec(m, bincode::config::standard()),
                WarmMLModelTrained::LogisticRegression(m) => bincode::serde::encode_to_vec(m, bincode::config::standard()),
            };
            
            let result = result.expect("An error occurred while encoding the model");

            fs::write(file_path, result).expect("An error occurred while saving the model");
        }
    }

    ///Loads a warm ml model from a file.
    /// # Arguments
    /// * `file_path` - The path to the model file
    /// * `algorithm` - The algorithm used during the training
    /// 
    /// # Returns
    /// A WarmMLModel object that uses the specified engine
    fn load(file_path: &str, algorithm: WarmMLModelAlgorithm) -> Result<WarmMLModel, io::Error>{
        let bytes = fs::read(file_path)?;

        // Load the model from file and return it based on the chosen algorithm
        match algorithm {
            WarmMLModelAlgorithm::Svm => {
                let (model,_): (Svm<f32, Pr>, usize) = bincode::serde::decode_from_slice(&bytes,bincode::config::standard())
                                                                        .expect(&format!("Error while loading the model from file {file_path}"));
                
                return Ok(WarmMLModel {
                    trained_model: Some(WarmMLModelTrained::Svm(model)),
                })
            },
            WarmMLModelAlgorithm::LogisticRegression  => {
                let (model,_): (FittedLogisticRegression<f32, bool>, usize) = bincode::serde::decode_from_slice(&bytes,bincode::config::standard())
                                                                                                                .expect(&format!("Error while loading the model from file {file_path}"));
                
                return Ok(WarmMLModel {
                    trained_model: Some(WarmMLModelTrained::LogisticRegression(model)),
                })
            },
        };
    }
}

pub struct WarmMLDatasetBuilder{
    samples_files: Vec<(WarmDatasetFileData, bool)>,
    join_handles: Vec<JoinHandle<(WarmDatasetFileData,bool)>>
}

impl WarmMLDatasetBuilder {
    
    /// Builds a WarmMLDataset that used calls to [WarmMLDatasetBuilder::add_file_async]
    pub fn build_async(mut self) -> WarmMLDataset {
        // Collect samples from every spawned thread and add it to the `samples_files`
    
        for join_handler in self.join_handles.drain(..) {
            let (file_data, label) = join_handler.join().unwrap();
            self.samples_files.push((file_data, label));
        }

        self.build()
    }

    /// Builds a WarmMLDataset
    pub fn build(mut self) -> WarmMLDataset{

        // Sort files by size
        self.samples_files.sort_by(|a, b| {
            a.0.samples.len().cmp(&b.0.samples.len())
        });

        WarmMLDataset { samples_files: self.samples_files }
    }

    /// Adds samples and their labels to the dataset from a file using threads.
    /// # Important
    /// You must call [WarmMLDataset::collect_file_data_async] after all [WarmMLDataset::add_file_async] to get results,
    /// otherwise there will be bugs.
    /// 
    /// # Arguments
    /// * `id` - An id associated to the samples found in this file.
    /// * `file_path` - The path to the json file to read.
    /// * `label` - The label to set for each sample. `true` for malicious data, `false` otherwise.
    pub fn add_file_async<T: WarmDatasetFileReader>(mut self, id: &str, file_path: &str, label: bool) -> Self {
        let id = String::from(id);
        let file_path = String::from(file_path);
        let label = label;
        let file = File::open(&file_path).expect(format!("Can't open file {file_path}").as_str());

        let join_handle = thread::spawn( move || {
            let file_data = WarmDatasetFileData::new(
                String::from(file_path),
                String::from(id),
                T::get_data(file)
            );
            (file_data, label)
        });

        self.join_handles.push(join_handle);
        self
    }

    /// Adds samples and their labels to the dataset from a file.
    /// 
    /// # Arguments
    /// * `id` - An id associated to the samples found in this file.
    /// * `file_path` - The path to the json file to read.
    /// * `label` - The label to set for each sample. `true` for malicious data, `false` otherwise.
    pub fn add_file<T: WarmDatasetFileReader>(mut self, id: &str, file_path: &str, label: bool) -> Self{
        let file = File::open(&file_path).expect(format!("Can't open file {file_path}").as_str());

        let file_data = WarmDatasetFileData::new(
            String::from(file_path),
            String::from(id),
            T::get_data(file)
        );

        //Add samples
        self.samples_files.push((file_data, label));

        self
    }

    /// Adds plain samples to the dataset
    /// 
    /// # Arguments
    /// * `id` - An id associated to the `samples`.
    /// * `samples` - A list of HTTP request.
    /// * `label` - Set to true if malicious, false otherwise.
    pub fn add_plain(mut self, id: &str, samples: Array1<Request<String>>, label: bool) -> Self{
        //Parse json
        let file_data: WarmDatasetFileData = WarmDatasetFileData { 
            file_path: String::from("(plain data)"),
            id: String::from(id),
            samples
        };

        //Add samples and label
        self.samples_files.push((file_data, label));

        self
    }
}

/// A struct to manage the training and test dataset used by the model.
/// # NOTE
/// - Samples are expected to be already URL encoded, otherwise something will crash.
/// - Labels are expected to be set to `true` for malicious samples and `false` for legitimate samples.
pub struct WarmMLDataset {
    samples_files: Vec<(WarmDatasetFileData, bool)>
}

impl Default for WarmMLDataset {
    fn default() -> Self {
        Self{
            samples_files: Vec::new()
        }
    }
}

impl WarmMLDataset {
    pub fn builder() -> WarmMLDatasetBuilder {
        WarmMLDatasetBuilder { samples_files: Vec::new(), join_handles: Vec::new() }
    }

    /// Randomly selects a subset of the available samples and makes a _copy_ of the [`WarmMLDataset`] with the reduced samples.
    /// Allows to create balanced and unblanaced classes for training using `legit_percentage`.
    /// Allows to reduce the dataset usage using `usage_percentage`.
    /// 
    /// 
    /// # Arguments
    /// * `usage_percentage` - Specifies the usage percentage of the total number of samples used.
    ///                        A value of 0 means that 0 samples will be used. A value of 100 means that all _possibile_ samples
    ///                        will be added. Note: a value of 100 doesn't grant that is going to be used the whole dataset because
    ///                        that also depends on the `legit_percentage` and the actual availability of samples by both classes.
    ///                        Values below 0 will be set to 0. Values greater than 100 will be set to 100.
    /// * `legit_percentage` - Specifies the percentage of legitimate samples in the total.
    ///                        A value of 100 means that will be used a dataset with only legitimate samples. A value of 0 instead
    ///                        will create a dataset with only malicious samples.
    ///                        Values below 0 will be set to 0. Values greater than 100 will be set to 100.
    /// * `seed` - The random number generator seed
    pub fn select_samples(&self, usage_percentage: f32, legit_percentage: f32, seed: u64) -> Self{
        let mut n_dataset_mal_samples = 0;
        let mut n_dataset_legit_samples = 0;
        let mut n_malicious_files = 0;
        let mut n_legitimate_files = 0;

        // Check `usage_percentage` value
        let usage_percentage = match usage_percentage {
            v if v < 0.0 => 0.0,
            v if v > 100.0 => 100.0,
            v => v,
        };

        // Check `legit_percentage` value
        let legit_percentage = match legit_percentage {
            v if v < 0.0 => 0.0,
            v if v > 100.0 => 100.0,
            v => v,
        };
        
        // Count the number of samples for each class
        for file_data in &self.samples_files {
            if file_data.1 == true {
                n_dataset_mal_samples += file_data.0.get_samples().len();
                n_malicious_files += 1;
            } else {
                n_dataset_legit_samples += file_data.0.get_samples().len();
                n_legitimate_files += 1;
            }
        }

        // Calculate malicious percentage
        let malicious_percentage = 100.0 - legit_percentage;

        // Take the minimum between the totals
        let n_samples_to_take = n_dataset_mal_samples.min(n_dataset_legit_samples);

        // Reduce `n_samples_to_take` by `usage_percentage`
        let n_samples_to_take = n_samples_to_take as f32 * usage_percentage / 100.0;

        // Calculate the number of samples to take for each class
        let n_samples_mal = n_samples_to_take * malicious_percentage / 100.0;
        let n_samples_legit = n_samples_to_take * legit_percentage / 100.0;

        // Calculate the number of samples to take for each file per class
        let mut malicious_samples_per_file: f32;
        if n_malicious_files == 0 {
            malicious_samples_per_file = 0.0;
        } else {
            malicious_samples_per_file = n_samples_mal / n_malicious_files as f32;
        }

        let mut legit_samples_per_file: f32;
        if n_legitimate_files == 0 {
            legit_samples_per_file = 0.0;
        } else {
            legit_samples_per_file = n_samples_legit / n_legitimate_files as f32;
        }

        let mut n_samples_mal_to_add = n_samples_mal as usize;
        let mut n_samples_legit_to_add = n_samples_legit as usize;

        let mut reduced_samples: Vec<(WarmDatasetFileData, bool)> = Vec::new();

        // For each file take the number of samples calculated.
        // If the number of samples to take is too big for a file distribute the samples not taken to the other files.
        for file_data in &self.samples_files {
            if file_data.1 == true {
                let reduced_file_data = WarmMLDataset::select_random_data(&file_data.0, malicious_samples_per_file as usize, seed);

                n_samples_mal_to_add -= reduced_file_data.samples.len();
                reduced_samples.push((reduced_file_data, true));

                // Update the samples to take for each file based on the quantity of samples added
                if n_malicious_files == 1 { continue; }
                n_malicious_files -= 1;
                malicious_samples_per_file = (n_samples_mal_to_add as f32) / n_malicious_files as f32;
            } else {
                let reduced_file_data = WarmMLDataset::select_random_data(&file_data.0, legit_samples_per_file as usize, seed);
                n_samples_legit_to_add -= reduced_file_data.samples.len();
                reduced_samples.push((reduced_file_data, false));
                
                // Update the samples to take for each file knowing `n_samples_not_taken`
                if n_legitimate_files == 1 { continue; }
                n_legitimate_files -= 1;
                legit_samples_per_file = (n_samples_legit_to_add as f32) / n_legitimate_files as f32;
            }
        }
        
        WarmMLDataset { 
            samples_files: reduced_samples
        }
    }

    /// Takes `n_samples` samples from `file_data` using the `seed` for the random selection and creates a new [`WarmDatasetFileData`].
    /// This function is private and should be used only by [`WarmMLDataset::select_samples`]
    /// 
    /// # Arguments
    /// * `file_data` -  The [`WarmDatasetFileData`] from which will be selected the data.
    /// * `n_samples` - The number of samples to take from the file.
    /// * `seed` - The seed to use for the random selection. 
    /// 
    /// # Returns
    /// In position 0 a new [`WarmDatasetFileData`] object with the `n_samples` specified.
    /// In position 1 the number of samples not taken if `n_samples` was too big for this file.
    fn select_random_data(file_data: &WarmDatasetFileData, mut n_samples: usize, seed: u64) -> WarmDatasetFileData {
        if n_samples == 0 {
            return WarmDatasetFileData::new(file_data.file_path.clone(), file_data.id.clone(), Array1::default(0));
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let file_data_samples_len = file_data.samples.len();

        // If `n_samples` is too big set it to the max possibile 
        if n_samples > file_data_samples_len {
            n_samples = file_data_samples_len;
        }

        // Randomly take `n_samples` from samples
        let mut indices: Vec<usize> = (0..n_samples).collect();
        indices.shuffle(&mut rng);

        let indices = &indices[0..n_samples];

        let reduced_samples = indices.iter().map(|&i| file_data.samples[i].clone()).collect::<Array1<_>>();
        let reduced_file_data = WarmDatasetFileData::new(file_data.file_path.clone(), file_data.id.clone(), reduced_samples);
        
        reduced_file_data
    }

    /// Gets all train samples for each train [`WarmDatasetFileData`] added.
    /// This function makes a copy of each sample vector so can be slow.
    /// If you only want the total number of samples use [WarmMLDataset::get_samples_len].
    pub fn get_samples(&self) -> Vec<Request<String>>{
        self.samples_files.iter().fold(Vec::<Request<String>>::new(), |mut acc: Vec<Request<String>> , file_data: &(WarmDatasetFileData, bool)| {
            acc.extend(file_data.0.get_samples().clone());
            acc
        })
    }

    /// Gets all labels for each [`WarmDatasetFileData`] added.
    pub fn get_labels(&self) -> Vec<bool>{
        self.samples_files.iter().fold(Vec::<bool>::new(), |mut acc, file_data| {
            let bool_array = Array1::<bool>::from_elem(file_data.0.samples.len(), file_data.1).to_vec();
            acc.extend(bool_array);
            acc
        })
    }

    /// Gets a reference to the internal samples vec
    pub fn get_files_samples(&self) -> &Vec<(WarmDatasetFileData, bool)> {
        &self.samples_files
    }

    /// Counts the number of samples added
    pub fn get_samples_len(&self) -> usize {
        let mut total = 0;
        for file_data in &self.samples_files {
            total += file_data.0.get_samples().len();
        }

        total
    }
}

/// A struct that represents the parsed data of a dataset file
pub struct WarmDatasetFileData {
    file_path: String,
    id: String,
    samples: Array1<Request<String>>,
}

impl WarmDatasetFileData {
    pub fn new(file_path: String, id: String, samples: Array1<Request<String>>) -> Self{
        Self {
            file_path, id, samples
        }
    }

    pub fn get_file_path(&self) -> &str {
        &self.file_path
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn get_samples(&self) -> &Array1<Request<String>> {
        &self.samples
    }
}



/// A trait for reading and parsing a file with structured data to be used in [`WarmMLDataset`]
pub trait WarmDatasetFileReader{
    /// Reads the given `file` and parses it to get an [`Array1<Request<String>`]
    /// 
    /// Arguments:
    /// * `file` - A [`File`] object of the file to parse
    fn get_data(file: std::fs::File) -> Array1<Request<String>>;
}

pub struct WarmDatasetFileReaderHelper;
impl WarmDatasetFileReaderHelper{
    /// Reads a CSV file and returns the parsed samples in the type `T`
    pub fn parse_csv<T: serde::de::DeserializeOwned + Debug>(file: File) -> Vec<T> {
        
        // Read csv file
        let mut rdr = csv::Reader::from_reader(file);
        let mut samples: Vec<T> = Vec::new();

        // Parse every record
        for result in rdr.deserialize() {
            let data: T = result.expect(format!("Error while parsing csv data").as_str());
            samples.push(data);
        }

        samples
    }

    /// Reads a JSON file and returns the parsed samples in the type `T`
    pub fn parse_json<T: serde::de::DeserializeOwned>(mut file: File) -> Vec<T> {
        let mut data_string: String = String::new();

        file.read_to_string(&mut data_string).expect("Error while reading json file");

        let samples: Vec<T> = serde_json::from_str(&data_string).expect(format!("Error while parsing json data").as_str());
        
        samples
    }

    /// Reads a JSONL file and returns the parsed samples in the type `T`
    pub fn parse_jsonl<T: serde::de::DeserializeOwned>(mut file: File) -> Vec<T> {
        let mut data_string: String = String::new();
        file.read_to_string(&mut data_string).expect("Error while reading json file");

        let mut samples: Vec<T> = Vec::new();
        for line in data_string.lines(){
            samples.push(
                serde_json::from_str(&line).expect(format!("Error while parsing json data").as_str())
            );
        }
        
        samples
    }

    pub fn get_protocol_version(s: &str) -> Option<Version>{
        match s {
            "HTTP/0.9" => Some(Version::HTTP_09),
            "HTTP/1.0" => Some(Version::HTTP_10),
            "HTTP/1.1" => Some(Version::HTTP_11),
            "HTTP/2" | "HTTP/2.0" => Some(Version::HTTP_2),
            "HTTP/3" | "HTTP/3.0" => Some(Version::HTTP_3),
            _ => None,
        }
    }

    pub fn get_method(s: &str) -> Option<Method> {
        match s {
            "GET" => Some(Method::GET),
            "POST" => Some(Method::POST),
            "PUT" => Some(Method::PUT),
            "DELETE" => Some(Method::DELETE),
            "PATCH" => Some(Method::PATCH),
            "HEAD" => Some(Method::HEAD),
            "OPTIONS" => Some(Method::OPTIONS),
            "CONNECT" => Some(Method::CONNECT),
            "TRACE" => Some(Method::TRACE),
            _ => None,
        }
    }
}