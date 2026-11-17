use std::sync::OnceLock;
use warm_ml::{ml_model::WarmModelLR, waf_engines::{ModSecEngine, ModSecEngineBuilder}, warm::Warm};

/// Global singleton.
///
/// Created exactly once during nginx bootstrap.
static WARM: OnceLock<Warm<ModSecEngine, WarmModelLR>> = OnceLock::new();

/// Initialize the global Warm instance.
///
/// This function must be called only once during
/// nginx module initialization.
///
/// The configuration parameters have already been
/// parsed from nginx.conf before calling this function.
pub fn init(config: &crate::config::WarmMainConfig) -> Result<(), InitError> {

    let model_path = config.model.as_ref().ok_or_else(|| InitError::InitializationFailed("Tried to load Warm without setting the model path".into()))?;
    let rules_dir = config.rules_dir.as_ref().ok_or_else(|| InitError::InitializationFailed("Tried to load Warm without setting rules directory".into()))?;

    let mut engine = ModSecEngineBuilder::new();
    for path in &config.config_files {
        engine = engine.with_config_file(path);
    }

    let engine = engine.with_rules_from_folder(&rules_dir).build();

    let warm = <Warm<ModSecEngine, WarmModelLR>>::load(model_path, engine)
        .map_err(
            |err| 
            InitError::InitializationFailed(
                Box::new(err)
            )
        )?;

    WARM
        .set(warm)
        .map_err(|_| InitError::AlreadyInitialized)
}

/// Retrieve the already-created Warm instance.
pub fn get() -> Option<&'static Warm<ModSecEngine, WarmModelLR>> {
    WARM.get()
}

/// Initialization errors.
#[derive(Debug)]
pub enum InitError {

    /// Warm was already initialized.
    AlreadyInitialized,

    /// Generic error for failed initialization. It contains the previous error.
    InitializationFailed(Box<dyn std::error::Error>),
}