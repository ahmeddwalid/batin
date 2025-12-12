//! High-performance batch processing with concurrency
//!
//! Provides async and parallel file processing capabilities.

use crate::{DetectionConfig, FileType, Result};
use futures::stream::{self, StreamExt};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Batch processor for scanning multiple files
pub struct BatchProcessor {
    config: DetectionConfig,
    /// Maximum concurrent file operations
    concurrency: usize,
}

impl BatchProcessor {
    /// Create a new batch processor with default concurrency (number of CPUs)
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            concurrency: num_cpus(),
        }
    }

    /// Create a batch processor with custom concurrency limit
    pub fn with_concurrency(config: DetectionConfig, concurrency: usize) -> Self {
        Self {
            config,
            concurrency: concurrency.max(1),
        }
    }

    /// Process multiple files asynchronously with parallel I/O
    ///
    /// Uses `buffer_unordered` for true parallel file processing, significantly
    /// faster than sequential processing for large directories.
    pub async fn process_directory<P: AsRef<Path>>(
        &self,
        dir: P,
        progress_tx: Option<mpsc::UnboundedSender<BatchProgress>>,
    ) -> Result<Vec<(PathBuf, Result<FileType>)>> {
        let mut entries = tokio::fs::read_dir(dir.as_ref()).await?;
        let mut paths = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            // Use async metadata check instead of blocking is_file()
            if let Ok(metadata) = tokio::fs::metadata(&path).await {
                if metadata.is_file() {
                    paths.push(path);
                }
            }
        }

        let total = paths.len();
        let config = self.config.clone();
        let concurrency = self.concurrency;

        // Create async stream with parallel processing
        let results: Vec<(PathBuf, Result<FileType>)> = stream::iter(paths)
            .enumerate()
            .map(|(idx, path)| {
                let config = config.clone();
                let progress_tx = progress_tx.clone();
                async move {
                    let result = FileType::from_file_path(&path, &config).await;

                    if let Some(tx) = progress_tx {
                        let _ = tx.send(BatchProgress {
                            processed: idx + 1,
                            total,
                            current_file: path.clone(),
                        });
                    }

                    (path, result)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        Ok(results)
    }

    /// Process directory recursively with parallel I/O
    pub async fn process_directory_recursive<P: AsRef<Path>>(
        &self,
        dir: P,
        progress_tx: Option<mpsc::UnboundedSender<BatchProgress>>,
    ) -> Result<Vec<(PathBuf, Result<FileType>)>> {
        let mut paths = Vec::new();

        // Collect all file paths recursively
        collect_files_recursive(dir.as_ref(), &mut paths).await?;

        let total = paths.len();
        let config = self.config.clone();
        let concurrency = self.concurrency;

        let results: Vec<(PathBuf, Result<FileType>)> = stream::iter(paths)
            .enumerate()
            .map(|(idx, path)| {
                let config = config.clone();
                let progress_tx = progress_tx.clone();
                async move {
                    let result = FileType::from_file_path(&path, &config).await;

                    if let Some(tx) = progress_tx {
                        let _ = tx.send(BatchProgress {
                            processed: idx + 1,
                            total,
                            current_file: path.clone(),
                        });
                    }

                    (path, result)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        Ok(results)
    }

    /// Process files in parallel using Rayon for CPU-bound entropy calculations
    pub fn process_parallel(&self, files: Vec<Vec<u8>>) -> Vec<Result<FileType>> {
        files
            .par_iter()
            .map(|data| FileType::from_bytes(data, &self.config))
            .collect()
    }
}

/// Recursively collect all file paths in a directory
async fn collect_files_recursive(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        // Use async metadata check instead of blocking is_file()/is_dir()
        if let Ok(metadata) = tokio::fs::metadata(&path).await {
            if metadata.is_file() {
                paths.push(path);
            } else if metadata.is_dir() {
                Box::pin(collect_files_recursive(&path, paths)).await?;
            }
        }
    }

    Ok(())
}

/// Get number of CPUs for default concurrency
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Progress information for batch operations
#[derive(Debug, Clone)]
pub struct BatchProgress {
    pub processed: usize,
    pub total: usize,
    pub current_file: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_cpus() {
        let cpus = num_cpus();
        assert!(cpus >= 1);
    }

    #[test]
    fn test_batch_processor_new() {
        let config = DetectionConfig::default();
        let processor = BatchProcessor::new(config);
        assert!(processor.concurrency >= 1);
    }

    #[test]
    fn test_batch_processor_with_concurrency() {
        let config = DetectionConfig::default();
        let processor = BatchProcessor::with_concurrency(config, 8);
        assert_eq!(processor.concurrency, 8);
    }
}
