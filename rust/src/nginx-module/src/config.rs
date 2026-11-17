use ngx::{ffi::ngx_flag_t, http::{Merge, MergeConfigError}};

/// This struct contains the global module configuration
#[repr(C)]
#[derive(Debug, Default)]
pub struct WarmMainConfig {
    /// Contains the CRS rules directory
    pub rules_dir: Option<String>,
    /// Contains the config files path
    pub config_files: Vec<String>,
    // Contains the warm model path
    pub model: Option<String>,
}

/// This struct contains the module configuration set for each location field
#[repr(C)]
#[derive(Debug, Default)]
pub struct WarmLocationConfig {
    /// Enables or disables request inspection.
    ///
    /// If set to `0` requests won't be evaluated by warm
    pub enabled: ngx_flag_t,
}

impl Merge for WarmLocationConfig {
    fn merge(&mut self, prev: &WarmLocationConfig) -> Result<(), MergeConfigError> {
        if self.enabled == ngx::ffi::NGX_CONF_UNSET as ngx_flag_t {
            self.enabled = prev.enabled;

            if self.enabled == ngx::ffi::NGX_CONF_UNSET as ngx_flag_t {
                self.enabled = 1;
            }
        }

        Ok(())
    }
}