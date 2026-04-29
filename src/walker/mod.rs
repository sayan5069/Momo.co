use crate::models::FileRecord;
use crate::hasher::hash_file;
use ignore::{WalkBuilder, WalkState};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use tracing::{error, info, debug};
use chrono::Utc;

pub struct Walker {
    root_path: PathBuf,
}

impl Walker {
    pub fn new<P: AsRef<Path>>(root_path: P) -> Self {
        Self {
            root_path: root_path.as_ref().to_path_buf(),
        }
    }

    pub fn walk(&self) -> Vec<FileRecord> {
        info!("Starting directory walk at: {:?}", self.root_path);
        
        let (tx, rx) = mpsc::channel();
        
        // Use WalkBuilder from ignore crate
        let walker = WalkBuilder::new(&self.root_path)
            .hidden(false) 
            .ignore(false) 
            .git_ignore(true) // Read .gitignore
            .add_custom_ignore_filename(".yomiignore")
            .build_parallel();

        walker.run(|| {
            let tx = tx.clone();
            let root_path = self.root_path.clone();
            
            Box::new(move |result| {
                let entry = match result {
                    Ok(entry) => entry,
                    Err(err) => {
                        error!("Error during walk: {}", err);
                        return WalkState::Continue;
                    }
                };

                let path = entry.path();
                
                // Skip directories
                if path.is_dir() {
                    return WalkState::Continue;
                }

                // Process file
                match process_file(path, &root_path) {
                    Ok(Some(record)) => {
                        let _ = tx.send(record);
                    }
                    Ok(None) => {},
                    Err(e) => {
                        error!("Failed to process file {:?}: {}", path, e);
                    }
                }

                WalkState::Continue
            })
        });

        drop(tx);

        let mut records = Vec::new();
        for record in rx {
            records.push(record);
        }

        info!("Walk completed. Found {} files.", records.len());
        records
    }
}

fn process_file(path: &Path, root_path: &Path) -> Result<Option<FileRecord>, Box<dyn std::error::Error>> {
    let metadata = path.symlink_metadata()?;
    
    let is_symlink = metadata.file_type().is_symlink();
    
    let path_str = path.to_string_lossy().to_string();
    let relative_path = path.strip_prefix(root_path)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
        
    let size_bytes = metadata.len();
    
    let mtime_unix = metadata.modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
        
    let extension = path.extension()
        .map(|e| e.to_string_lossy().to_string())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();
        
    let hash = match hash_file(path) {
        Ok(h) => h,
        Err(e) => {
            debug!("Could not hash {:?}: {}", path, e);
            return Ok(None);
        }
    };
    
    let language = extension_to_language(&extension);

    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        format!("{:o}", metadata.permissions().mode() & 0o777)
    };
    
    #[cfg(not(unix))]
    let permissions = String::from("644");

    Ok(Some(FileRecord {
        path: path_str,
        relative_path,
        hash,
        size_bytes,
        mtime_unix,
        language,
        extension,
        is_binary: false, // proper logic later
        is_symlink,
        permissions,
        indexed_at: Utc::now().to_rfc3339(),
    }))
}

fn extension_to_language(ext: &str) -> String {
    match ext {
        ".rs" => "Rust",
        ".js" => "JavaScript",
        ".ts" => "TypeScript",
        ".py" => "Python",
        ".md" => "Markdown",
        ".json" => "JSON",
        ".toml" => "TOML",
        ".yml" | ".yaml" => "YAML",
        ".c" => "C",
        ".cpp" | ".cc" | ".cxx" => "C++",
        ".go" => "Go",
        ".java" => "Java",
        ".html" => "HTML",
        ".css" => "CSS",
        _ => "Unknown",
    }.to_string()
}
