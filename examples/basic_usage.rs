use batin::{DetectionConfig, FileType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Detect from bytes
    let suspicious_data = std::fs::read("suspicious.exe")?;
    let config = DetectionConfig::default();

    match FileType::from_bytes(&suspicious_data, &config) {
        Ok(file_type) => {
            println!(
                "Detected: {} ({})",
                file_type.extension, file_type.mime_type
            );
            println!("Threat Level: {:?}", file_type.threat_level);

            if let Some(entropy) = file_type.entropy_profile {
                println!("Global Entropy: {:.2}", entropy.global_entropy);
                if entropy.is_packed {
                    println!("⚠️  WARNING: File appears to be packed!");
                }
            }

            if file_type.detected_formats.len() > 1 {
                println!("⚠️  POLYGLOT DETECTED: {:?}", file_type.detected_formats);
            }
        }
        Err(e) => eprintln!("Detection failed: {}", e),
    }

    // Example 2: Detect from file path with extension validation
    let result = FileType::from_file_path("document.pdf", &config).await?;

    if !result.validate_extension("pdf") {
        eprintln!("⚠️  Extension mismatch detected!");
    }

    // Example 3: Batch processing
    use batin::BatchProcessor;

    let processor = BatchProcessor::new(config);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<batin::BatchProgress>();

    let handle = tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            println!("Progress: {}/{}", progress.processed, progress.total);
        }
    });

    let results = processor.process_directory("./samples", Some(tx)).await?;
    handle.await?;

    for (path, result) in results {
        match result {
            Ok(ft) => println!(
                "{}: {} (threat: {:?})",
                path.display(),
                ft.extension,
                ft.threat_level
            ),
            Err(e) => eprintln!("{}: Error - {}", path.display(), e),
        }
    }

    Ok(())
}
