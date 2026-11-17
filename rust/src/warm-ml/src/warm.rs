use std::io;

use crate::{dataset::{WarmDataset, WarmDatasetFile}, ml_model::*, waf_engines::WafEngine};
use http::Request;
use linfa::{dataset::Pr, metrics::{ConfusionMatrix, ToConfusionMatrix}};
use ndarray::{Array1, ArrayView1, Axis};

pub trait WarmEvaluator {
    fn evaluate(&self, req: &Request<String>) -> WarmVerdict;
}

/// The result of a [`Warm`] evaluation.
pub struct WarmVerdict {
    /// Tells if the evaluated request is safe or not based on the used `threshold`
    safe: bool,
    /// Model prediction score of the evaluated request 
    score: Pr,
}

impl WarmVerdict {
    /// Creates new WarmVerdict.
    ///
    /// # Arguments
    /// * `safe`: bool - Sets the result as a safe request
    /// * `used_threshold` - The used threshold during the evaluation
    /// * `score` - The score given by the model
    pub fn new(safe: bool, score: Pr) -> Self{
        WarmVerdict {
            safe,
            score
        }
    }

    /// Tells if the evaluated request is safe
    pub fn is_safe(&self) -> bool{
        self.safe
    }

    /// Tells if the evaluated request is malicious
    pub fn is_malicious(&self) -> bool{
        !self.safe
    }

    pub fn get_score(&self) -> f32 {
        self.score.abs()
    }
}

/// The main API endpoint. Allows to evaluate requests with a [`WarmModel`] using the associated [`WafEngine`]
pub struct Warm<W: WafEngine, M: WarmModel>{
    /// The ml model used for evaluating requests
    model: M,
    /// The engine used by the model and used as default in case of an untrained model.
    waf_engine: W,
    /// If a request has a malicious probability greater than `threshold`, the verdict will be set as unsafe.
    threshold: Pr,
}

impl<W: WafEngine, M: WarmModel> WarmEvaluator for Warm<W, M> {
    /// Evaluates a [`Request<String>`]. If you already have the request features then use [Warm::evaluate_features] .
    /// # Note 
    /// Can happen that a [`WafEngine`] finds rules unknown to the model. In this case the request will be evaluated
    /// using [Warm::evaluate_vanilla] and a warning will be printed out on the screen.
    /// 
    /// # Returns
    /// A [`WarmVerdict`] with the results. 
    fn evaluate(&self, req: &Request<String>) -> WarmVerdict {
        let features = WarmFeaturesExtractor::get_features_from_request(&self.waf_engine, req);
        
        // If extraction is Ok then use it otherwise use the waf engine for evaluation and return the result
        match features {
            Err(v) => {
                println!("WARNING: The model couldn't evaluate the request because it triggered an unknown rule with id {v}. Using the waf engine for evaluation.");
                return self.evaluate_vanilla(req)
            },
            _ => {}
        }

        let features = features.unwrap();
        self.evaluate_features(features.view())
    }
}

impl<W: WafEngine, M: WarmModel> Warm<W, M>{
    /// Creates new [`Warm`] object with the given parameters.
    /// By default the threshold is set to [Pr::even()]
    pub fn new(model: M, waf_engine: W) -> Self{
        Self {
            model,
            waf_engine,
            threshold: Pr::even(),
        }
    }

    /// Sets threshold of [`Warm`]
    pub fn set_threshold(mut self, threshold: Pr) -> Self{
        self.threshold = threshold;

        self
    }

    /// Gets threshold of [`Warm`]
    pub fn get_threshold(&self) -> f32{
        *self.threshold
    }

    /// Evaluate a request using its features.
    /// 
    /// # Note 
    /// Can happen that a [`WafEngine`] finds rules unknown to the model. In this case the request will be evaluated
    /// using [Warm::evaluate_vanilla] and a warning will be printed out on the screen.
    /// 
    /// # Returns
    /// A [`WarmVerdict`] with the results.
    /// 
    /// # Errors
    /// Panics if `features` has the wrong size.
    pub fn evaluate_features(&self, features: ArrayView1<f32>) -> WarmVerdict{
        let features = features
            .to_shape((1, features.len()))
            .expect("You tried to evaluate features with a wrong sized array. Be sure to use WarmFeaturesExtractor to get features.");

        let scores = self.model.predict(features.view());
        let score = scores[0];

        let is_safe = score < self.threshold;

        WarmVerdict::new(is_safe, score)
    }

    pub fn test_dataset(&self, feature_dataset: &WarmFeatureDataset) -> ConfusionMatrix<bool>
    {
        let features_list = feature_dataset.get_features_list();
        let labels = feature_dataset.get_labels_list();
        let results = features_list.axis_iter(Axis(0)).map(|x| {
            self.evaluate_features(x).is_malicious()
        }).collect::<Array1<bool>>();

        results.confusion_matrix(labels).expect("An error occurred in test")
    }

    /// Evaluates the given request using directly a [`WafEngine`].
    /// 
    /// # Returns
    /// A [`WarmVerdict`] with the results.
    pub fn evaluate_vanilla(&self, req: &http::Request<String>) -> WarmVerdict {
        self.waf_engine.evaluate(req)
    }

    pub fn get_waf_engine(&self) -> &W {
        &self.waf_engine
    }

    pub fn get_model(&self) -> &M {
        &self.model
    }

    /// Loads a [`WarmModel`] from a file and creates a [`Warm`] object that uses it.
    /// 
    /// # Arguments
    /// * `file_path` - The complete path to a model file
    /// * `waf_engine` - The same [`WafEngine`] used by the model
    /// 
    /// # Returns
    /// A [`Warm`] object if the model is loaded successfully.
    /// An [`io::Error`] if the file in the given `file_path` is not found. 
    pub fn load(file_path: &str, waf_engine: W) -> Result<Warm<W, M>, io::Error>{
        let model = M::load(file_path)?;
        
        Ok(
            Warm { 
                model, 
                waf_engine, 
                threshold: Pr::even(),
            }
        )
    }
}