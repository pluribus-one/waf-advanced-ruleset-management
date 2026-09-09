use std::{collections::HashMap, ffi::OsStr};
use std::fs;
use modsecurity::Rules;
use regex::Regex;

use http::{Request, Version};
use modsecurity::{ModSecurity};

/// Represents a SecRule
pub struct SecRule {
    /// The SecRule id
    id: i64
}

impl SecRule {
    /// Extracts a [`SecRule`] list from the given file
    /// 
    /// # Returns
    /// A [`Vec<SecRule>`] of the read file.
    fn extract_from_file(file_path: &str) -> Vec<SecRule> {
        let content = fs::read_to_string(file_path).expect(format!("The file {} can't be read.", file_path).as_str());

        let normalized = content.replace("\\\n", " ");

        let re = Regex::new(r"id\s*:\s*(\d+)").expect("Should always compile");

        let mut rules: Vec<SecRule> = Vec::new();

        for cap in re.captures_iter(&normalized) {
            if let Ok(id) = cap[1].parse::<i64>() {
                rules.push(SecRule {
                    id
                });
            }
        }

        rules
    }

    pub fn get_id(&self) -> i64{
        self.id
    }
}

pub trait WafEngine: Default{
    /// Gets the rules added in this engine
    fn get_rules(&self) -> &Vec<SecRule>;
    /// Gets the number of rules added in this engine
    fn get_num_rules(&self) -> usize;

    ///Evaluates a request against the added rules and gives a list of the rules triggered
    fn evaluate(&self, req: &Request<String>) -> Vec<SecRule>;

    ///Evaluates a request and tells if the WAF wants to block it
    fn should_block(&self, req: &Request<String>) -> bool;

    ///Gets the secrule index inside the internal vec.
    /// 
    /// # Returns
    /// - [`None`] when called with a rule_id that has not been added. 
    /// - [`Some`] of an index when found
    fn get_rule_index(&self, rule_id: i64) -> Option<&usize>;
}

/// A builder for [`ModSecEngine`]. It helps adding the rules.
pub struct ModSecEngineBuilder {
    ///A ModSecurity object
    ms: ModSecurity,
    ///The rules used in a transaction
    ms_rules: Rules,
    ///The rules added and used by the engine.
    /// # IMPORTANT
    /// Every added rule must be added to `ms_rules` and to `secrulesid_bind` too.
    secrules: Vec<SecRule>,
    ///Maps each SecRule id to its index in `secrules`.
    secrulesid_bind: HashMap<i64, usize>,
}

impl ModSecEngineBuilder {
    pub fn new() -> Self {
        Self {
            ms: ModSecurity::builder().with_log_callbacks().build(),
            ms_rules: Rules::new(),
            secrules: Vec::new(),
            secrulesid_bind: HashMap::new(),
        }
    }

    /// Adds the config file found in `file_path` to the final [`ModSecEngine`].
    /// This function must be used for config files instead of [ModSecEngineBuilder::with_rules_from_file]
    pub fn with_config_file(mut self, file_path: &str) -> Self {
        self.ms_rules.add_file(file_path).expect("An error occurred while adding the conf file");

        self
    }

    /// Adds the rules found in `file_path` to the final [`ModSecEngine`].
    pub fn with_rules_from_file(mut self, file_path: &str) -> Self {
        //Add rules to secrules Vec
        self.secrules.append(&mut SecRule::extract_from_file(file_path));
        self.ms_rules.add_file(file_path).expect("An error occurred while adding the conf file");

        self

    }

    /// Adds the rules from the files found in `folder_path` which have a name that matches `file_name_regex`
    /// to the final [`ModSecEngine`].
    pub fn with_rules_from_files(mut self, folder_path: &str, file_name_regex: &str) -> Self {
        let files = fs::read_dir(folder_path).expect(format!("Directory {folder_path} not found").as_str());
        let regex = Regex::new(file_name_regex).expect("Error while compiling the file name regex");

        //Loop through each file
        for file in files {
            match file {
                Ok(entry) => {
                    //This is the rule file path
                    let path = entry.path();
                    if !path.is_file(){
                        continue;
                    }

                    let path = path.to_str();
                    if let Some(path) = path && regex.is_match(path){
                        self.ms_rules.add_file(path).expect("An error occurred while loading the rule, probably a syntax error.");
                        self.secrules.append(
                            &mut SecRule::extract_from_file(path)
                        );
                    }
                }
                Err(e) => {
                    println!("An error occurred while reading a file: {}", e);
                }
            }
        }

        self
    }

    /// Adds the rules found in the `folder_path` to the final [`ModSecEngine`].
    /// This function loops through each .conf file in a given folder and loads it.
    /// 
    /// # Attention
    /// The config files like _modsecurity.conf_ and _crs-setup.conf_ must be loaded with [ModSecEngineBuilder::with_config_file]
    /// before calling this function.
    /// 
    /// # Arguments
    /// * `folder_path` - The folder which will be read for getting all config files (.conf files)
    pub fn with_rules_from_folder(mut self, folder_path: &str) -> Self {
        let files = fs::read_dir(folder_path).expect(format!("Directory {folder_path} not found").as_str());

        //Loop through each file
        for file in files {
            match file {
                Ok(entry) => {
                    //This is the rule file path
                    let path = entry.path();
                    let extension = path.extension().unwrap_or_default();
                    if extension == OsStr::new("conf"){
                        let path = path.to_str();
                        if let Some(path) = path {
                            self.ms_rules.add_file(path).expect("An error occurred while loading the rule, probably a syntax error.");
                            self.secrules.append(
                                &mut SecRule::extract_from_file(path)
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("An error occurred while reading a file: {}", e);
                }
            }
        }

        self
    }

    /// Builds a ModSecEngine
    pub fn build(mut self) -> ModSecEngine {
        //Update the secrules id bindings
        for (i, rule) in self.secrules.iter().enumerate(){
            self.secrulesid_bind.insert(rule.get_id(), i);
        }

        ModSecEngine::new(self.ms, self.ms_rules, self.secrules, self.secrulesid_bind)
    }
}

pub struct ModSecEngine {
    ///A ModSecurity object
    ms: ModSecurity,
    ///The rules used in a transaction
    ms_rules: Rules,
    ///The rules added and used by the engine. Every rule must be added to ms_rules.
    secrules: Vec<SecRule>,
    ///Maps the rule ids to their position in secrules Vec
    secrulesid_bind: HashMap<i64, usize>,
}

impl Default for ModSecEngine {
    fn default() -> Self {
        Self {
            ms: ModSecurity::builder().with_log_callbacks().build(),
            ms_rules: Rules::new(),
            secrules: Vec::new(),
            secrulesid_bind: HashMap::new(),
        }
    }
}

impl WafEngine for ModSecEngine{
    fn get_rules(&self) -> &Vec<SecRule> {
        &self.secrules
    }

    fn get_num_rules(&self) -> usize {
        self.secrules.len()
    }

    /// For general documentation check [WafEngine::evaluate].
    /// # NOTE
    /// At the moment evaluates only the URI and headers of a request.
    /// To evaluate also the request body [ModSecEngine::process_request] must be modified.
    fn evaluate(&self, req: &Request<String>) -> Vec<SecRule> {
        let mut triggered_rules: Vec<SecRule> = Vec::new();

        let mut transaction = self.ms.transaction_builder()
        .with_rules(&self.ms_rules)
        .build().expect("Error building transaction");

        self.process_request(&mut transaction, &req);

        //Loop through each matched rule and add it into the triggered rules
        for rule in transaction.matched_rules() {
            triggered_rules.push(SecRule { 
                id: rule.rule_id
            });
        }

        triggered_rules
    }

    fn get_rule_index(&self, rule_id: i64) -> Option<&usize> {
        self.secrulesid_bind.get(&rule_id)
    }
    
    fn should_block(&self, req: &Request<String>) -> bool {
        let mut transaction = self.ms.transaction_builder()
        .with_rules(&self.ms_rules)
        .build().expect("Error building transaction");
    
        self.process_request(&mut transaction, &req);
        
        //Check if ModSecurity wants to block the request
        let intervention = transaction.intervention();

        if let Some(intervention) = intervention {
            intervention.disruptive()
        } else {
            false
        }
    }
    
    
}

impl ModSecEngine {
    fn new(ms: ModSecurity, ms_rules: Rules, secrules: Vec<SecRule>, secrulesid_bind: HashMap<i64, usize>) -> Self{
        Self {
            ms,ms_rules,secrules,secrulesid_bind
        }
    }

    /// Helper method for [ModSecEngine::evaluate] which takes an initialized transaction and process the given request.
    fn process_request(&self, transaction: &mut modsecurity::Transaction, req: &Request<String>){
    
        // Add request headers to transaction
        for (key,value) in req.headers() {
            transaction.add_request_header(key.as_str(), value.to_str().unwrap_or_default())
                .expect(format!(
                    "Modsecurity error while adding the request header with name {} and value {}",
                    key.as_str(), 
                    value.to_str().unwrap_or_default()
                ).as_str());
        }

        // Add request body to transaction
        transaction.append_request_body(req.body().as_bytes()).expect(
            format!("Modsecurity error while adding the request body with value: {}",req.body().as_str())
        .as_str());
        

        let uri = req.uri().to_string();
        let version_str = match req.version() {
            Version::HTTP_09 => "0.9",
            Version::HTTP_10 => "1.0",
            Version::HTTP_11 => "1.1",
            Version::HTTP_2 => "2",
            Version::HTTP_3 => "3",
            _ => "1.1" //Default to HTTP/1.1 if not recognized
        };

        transaction.process_uri(&uri, req.method().as_str(), version_str).expect("Error while processing request uri");
        transaction.process_request_headers().expect("Error while processing request headers");
        transaction.process_request_body().expect("Error while processing request body");

    }
}

pub struct MockEngine {
    secrules: Vec<SecRule>,
    secrules_bind: HashMap<i64, usize>,
}

impl Default for MockEngine{
    fn default() -> Self {
        let rules = vec![
                SecRule{id: 1}, //If uri contains admin
                SecRule{id: 2}, //If uri contains test
                SecRule{id: 3}, //If uri contains <script>
                SecRule{id: 4}, //If uri contains %00
        ];

        let mut secrules_bind: HashMap<i64, usize> = HashMap::new();
        for (i, rule ) in rules.iter().enumerate() {
            let id = rule.get_id();
            secrules_bind.insert(id, i);
        }
        
        Self { 
            secrules: rules,
            secrules_bind: secrules_bind,
        }
    }
}

impl WafEngine for MockEngine{
    fn get_rules(&self) -> &Vec<SecRule> {
        &self.secrules
    }
    
    fn get_num_rules(&self) -> usize {
        self.secrules.len()
    }
    
    fn evaluate(&self, req: &Request<String>) -> Vec<SecRule> {
        let mut triggered_rules: Vec<SecRule> = Vec::new();

        if req.uri().to_string().contains("admin") {
            triggered_rules.push(SecRule { id: 1 });
        }
        if req.uri().to_string().contains("test") {
            triggered_rules.push(SecRule { id: 2 });
        }
        if req.uri().to_string().contains("<script>") {
            triggered_rules.push(SecRule { id: 3 });
        }
        if req.uri().to_string().contains("\0") {
            triggered_rules.push(SecRule { id: 4 });
        }

        triggered_rules
    }
    
    fn should_block(&self, req: &Request<String>) -> bool {
        self.evaluate(req).len() > 0
    }
    
    fn get_rule_index(&self, rule_id: i64) -> Option<&usize> {
        self.secrules_bind.get(&rule_id)
    }
}