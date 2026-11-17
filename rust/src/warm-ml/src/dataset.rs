use ndarray::{Array1};
use rand::{rngs::StdRng, seq::{SliceRandom}, *};
use std::{fmt::Debug, fs::File, io::Read, };
use http::{Method, Request, Version};

/// A builder for a [`WarmDataset`]
pub struct WarmDatasetBuilder{
    files: Vec<WarmDatasetFile>,
}

impl WarmDatasetBuilder {
    /// Builds a WarmDataset
    pub fn build(&self) -> WarmDataset{
        WarmDataset {files: self.files.to_owned()}
    }

    pub fn build_with(&self, usage_percentage: f32, legitimate_percentage: f32, seed: u64) -> WarmDataset {
        #[derive(Default)]
        struct ClassCounters {
            files_left: usize,
            samples_left: usize,
        }

        let malicious_percentage = 100.0 - legitimate_percentage;

        // Count files and samples

        let mut malicious = ClassCounters::default();
        let mut legitimate = ClassCounters::default();

        let mut malicious_samples = 0;
        let mut legitimate_samples = 0;

        for file in &self.files {
            if file.is_malicious {
                malicious.files_left += 1;
                malicious_samples += file.samples.len();
            } else {
                legitimate.files_left += 1;
                legitimate_samples += file.samples.len();
            }
        }

        let max_samples = malicious_samples.min(legitimate_samples);
        let max_samples = (max_samples as f32 * usage_percentage / 100.0) as usize;

        malicious.samples_left = (max_samples as f32 * malicious_percentage / 100.0) as usize;
        legitimate.samples_left = (max_samples as f32 * legitimate_percentage / 100.0) as usize;

        // Sort files by size
        let mut files: Vec<&WarmDatasetFile> = self.files.iter().collect();
        files.sort_by(|a, b| {
            a.samples.len().cmp(&b.samples.len())
        });

        // Build new dataset

        let mut new_files = Vec::with_capacity(files.len());

        for file in files {
            let counters = if file.is_malicious {
                &mut malicious
            } else {
                &mut legitimate
            };

            let samples_to_take = counters.samples_left.checked_div(counters.files_left);
            let samples_to_take = match samples_to_take {
                None => 0,
                Some(v) => v
            };
            let samples = Self::take_random_samples(&file.samples, samples_to_take, seed);

            counters.files_left -= 1;
            counters.samples_left -= samples.len();

            new_files.push(WarmDatasetFile {
                file_path: file.file_path.clone(),
                name: file.name.clone(),
                is_malicious: file.is_malicious,
                samples,
            });
        }

        WarmDataset { files: new_files }
    }

    fn take_random_samples(samples: &Array1<Request<String>>, mut n_samples: usize, seed: u64) -> Array1<Request<String>> {
        if n_samples == 0 {
            return Array1::default(0);
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let file_data_samples_len = samples.len();

        // If `n_samples` is too big set it to the max possibile 
        if n_samples > file_data_samples_len {
            n_samples = file_data_samples_len;
        }

        // Randomly take `n_samples` from samples
        let mut indices: Vec<usize> = (0..n_samples).collect();
        indices.shuffle(&mut rng);

        let indices = &indices[0..n_samples];
        
        //Collect reduced samples
        indices.iter().map(|&i| samples[i].clone()).collect::<Array1<_>>()
    }

    /// Adds samples and their labels to the dataset from a file.
    /// 
    /// # Arguments
    /// * `id` - An id associated to the samples found in this file.
    /// * `file_path` - The path to the json file to read.
    /// * `is_malicious` - The label to set for each sample. `true` for malicious data, `false` otherwise.
    pub fn add_file<T: WarmFileReader>(mut self, id: &str, file_path: &str, is_malicious: bool) -> Self{
        let file = File::open(file_path).unwrap_or_else(|_| panic!("Can't open file {file_path}"));

        let file_data = WarmDatasetFile::new(
            String::from(file_path),
            String::from(id),
            T::get_data(file),
            is_malicious
        );

        //Add samples
        self.files.push(file_data);

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
        let file_data: WarmDatasetFile = WarmDatasetFile { 
            file_path: String::from("(plain data)"),
            name: String::from(id),
            samples,
            is_malicious: label
        };

        //Add samples and label
        self.files.push(file_data);

        self
    }

    pub fn get_files(&self) -> &Vec<WarmDatasetFile> {
        &self.files
    }
}

/// A struct to manage the training and test dataset used by the model.
/// 
/// # NOTE
/// - Samples are expected to be already URL encoded, otherwise something will crash.
/// - Labels are expected to be set to `true` for malicious samples and `false` for legitimate samples.
#[derive(Clone)]
pub struct WarmDataset {
    files: Vec<WarmDatasetFile>
}

impl WarmDataset {
    pub fn builder() -> WarmDatasetBuilder {
        WarmDatasetBuilder { files: Vec::new() }
    }

    pub fn get_samples(&self) -> Vec<&Request<String>>{
        let mut samples: Vec<&Request<String>> = Vec::with_capacity(self.get_samples_count());

        for file in &self.files {
            for sample in &file.samples {
                samples.push(sample);
            }
        }

        samples
    }

    /// Gets a reference to the internal files vec
    pub fn get_files(&self) -> &Vec<WarmDatasetFile> {
        &self.files
    }

    /// Counts the number of samples added
    pub fn get_samples_count(&self) -> usize {
        let mut total = 0;
        for file in &self.files {
            total += file.get_samples_count();
        }

        total
    }

    /// Counts the number of malicious samples added
    pub fn get_malicious_samples_count(&self) -> usize {
        let mut total = 0;
        for file in &self.files {
            if file.is_malicious {
                total += file.get_samples_count();
            }
        }

        total
    }

    /// Counts the number of legitimate samples added
    pub fn get_legitimate_samples_count(&self) -> usize {
        let mut total = 0;
        for file in &self.files {
            if !file.is_malicious {
                total += file.get_samples_count();
            }
        }

        total
    }
}

/// A struct that represents the parsed data of a dataset file
#[derive(Clone)]
pub struct WarmDatasetFile {
    name: String,
    file_path: String,
    samples: Array1<Request<String>>,
    is_malicious: bool,
}

impl WarmDatasetFile {
    pub fn new(file_path: String, name: String, samples: Array1<Request<String>>, is_malicious: bool) -> Self{
        Self {
            file_path, name, samples, is_malicious
        }
    }

    pub fn get_file_path(&self) -> &str {
        &self.file_path
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_label(&self) -> bool {
        self.is_malicious
    }

    pub fn get_samples(&self) -> &Array1<Request<String>> {
        &self.samples
    }

    pub fn get_samples_count(&self) -> usize {
        self.samples.len()
    }

    pub fn get_normalized_name(&self) -> String {
        String::from(self.name.to_lowercase().replace(" ", "_").replace(".", "-").trim())
    }
}



/// A trait for reading and parsing a file with structured data to be used in [`WarmDatasetBuilder`]
pub trait WarmFileReader{
    /// Reads the given `file` and parses it to get an [`Array1<Request<String>`]
    /// 
    /// Arguments:
    /// * `file` - A [`File`] object of the file to parse
    fn get_data(file: std::fs::File) -> Array1<Request<String>>;
}

/// A collection of common functions for [WarmDatasetFileReader] implementations.
pub struct WarmFileReaderCommons;
impl WarmFileReaderCommons{
    /// Reads a CSV file and returns the parsed samples in the type `T`
    pub fn parse_csv<T: serde::de::DeserializeOwned + Debug>(file: File) -> Vec<T> {
        
        // Read csv file
        let mut rdr = csv::Reader::from_reader(file);
        let mut samples: Vec<T> = Vec::new();

        // Parse every record
        for result in rdr.deserialize() {
            let data: T = result.expect("Error while parsing csv data");
            samples.push(data);
        }

        samples
    }

    /// Reads a JSON file and returns the parsed samples in the type `T`
    pub fn parse_json<T: serde::de::DeserializeOwned>(mut file: File) -> Vec<T> {
        let mut data_string: String = String::new();

        file.read_to_string(&mut data_string).expect("Error while reading json file");

        let samples: Vec<T> = serde_json::from_str(&data_string).expect("Error while parsing json data");
        
        samples
    }

    /// Reads a JSONL file and returns the parsed samples in the type `T`
    pub fn parse_jsonl<T: serde::de::DeserializeOwned>(mut file: File) -> Vec<T> {
        let mut data_string: String = String::new();
        file.read_to_string(&mut data_string).expect("Error while reading json file");

        let mut samples: Vec<T> = Vec::new();
        for line in data_string.lines(){
            samples.push(
                serde_json::from_str(&line).expect("Error while parsing json data")
            );
        }
        
        samples
    }
}

pub struct WarmFileReaderUtils;
impl WarmFileReaderUtils {
    /// Gets a [Version] enum from a [str].
    /// 
    /// # Returns
    /// - [None] if the string is not recognized
    /// - [Version] of the parsed `version_str`
    pub fn get_protocol_version(version_str: &str) -> Option<Version>{
        match version_str {
            "HTTP/0.9" => Some(Version::HTTP_09),
            "HTTP/1.0" => Some(Version::HTTP_10),
            "HTTP/1.1" => Some(Version::HTTP_11),
            "HTTP/2" | "HTTP/2.0" => Some(Version::HTTP_2),
            "HTTP/3" | "HTTP/3.0" => Some(Version::HTTP_3),
            _ => None,
        }
    }

    /// Gets a [Method] enum from a [str].
    /// 
    /// # Returns
    /// - [None] if the string is not recognized
    /// - [Method] of the parsed `method_str`
    pub fn get_method(method_str: &str) -> Option<Method> {
        match method_str {
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