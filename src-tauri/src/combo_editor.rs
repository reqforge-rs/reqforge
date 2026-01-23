use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use rand::Rng;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransformConfig {
    // Length filter
    pub length_filter_enabled: bool,
    pub length_min: usize,
    pub length_max: usize,

    // Domain switcher
    pub domain_switch_enabled: bool,
    pub domain_switch_all: bool,
    pub domain_old: String,
    pub domain_new: String,

    // Special char
    pub special_char_enabled: bool,
    pub special_char: String,
    pub special_char_position: String, // "start", "end", "random"

    // Simple toggles
    pub uppercase_first: bool,
    pub remove_duplicates: bool,
    pub remove_letters_only: bool,
    pub remove_numbers_only: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransformResult {
    pub original_count: usize,
    pub new_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransformProgress {
    pub phase: String,
    pub processed: usize,
    pub total: usize,
    pub percent: f32,
}

const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~";

fn has_special_char(s: &str) -> bool {
    s.chars().any(|c| SPECIAL_CHARS.contains(c))
}

fn is_letters_only(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_numbers_only(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn split_combo(line: &str) -> Option<(String, String)> {
    // Try common delimiters: : ; | ,
    for delim in [':', ';', '|', ','] {
        if let Some(pos) = line.find(delim) {
            let user = line[..pos].to_string();
            let pass = line[pos + 1..].to_string();
            if !user.is_empty() && !pass.is_empty() {
                return Some((user, pass));
            }
        }
    }
    None
}

fn get_domain(email: &str) -> Option<&str> {
    if let Some(at_pos) = email.find('@') {
        Some(&email[at_pos + 1..])
    } else {
        None
    }
}

fn replace_domain(email: &str, new_domain: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        format!("{}@{}", &email[..at_pos], new_domain)
    } else {
        email.to_string()
    }
}

/// Hash a line for memory-efficient deduplication
fn hash_line(line: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    line.hash(&mut hasher);
    hasher.finish()
}

/// Count lines in a file efficiently
fn count_lines(path: &Path) -> std::io::Result<usize> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(1024 * 1024, file); // 1MB buffer
    Ok(reader.lines().count())
}

/// Apply a single-line transform (doesn't need global state)
fn transform_line(line: String, config: &TransformConfig, modified: &mut bool) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Parse combo
    let (user, pass) = match split_combo(trimmed) {
        Some(combo) => combo,
        None => return Some(line), // Keep non-combo lines
    };

    // Length filter
    if config.length_filter_enabled {
        let len = pass.len();
        if len < config.length_min || len > config.length_max {
            return None;
        }
    }

    // Remove letters-only passwords
    if config.remove_letters_only && is_letters_only(&pass) {
        return None;
    }

    // Remove numbers-only passwords
    if config.remove_numbers_only && is_numbers_only(&pass) {
        return None;
    }

    let mut current_user = user;
    let mut current_pass = pass;
    let mut was_modified = false;

    // Domain switcher
    if config.domain_switch_enabled && !config.domain_new.is_empty() {
        let should_switch = if config.domain_switch_all {
            current_user.contains('@')
        } else {
            get_domain(&current_user)
                .map(|d| d.eq_ignore_ascii_case(&config.domain_old))
                .unwrap_or(false)
        };

        if should_switch {
            current_user = replace_domain(&current_user, &config.domain_new);
            was_modified = true;
        }
    }

    // Add special character
    if config.special_char_enabled && !config.special_char.is_empty() && !has_special_char(&current_pass) {
        let chars: Vec<char> = config.special_char.chars().collect();
        let char_to_add = if chars.len() == 1 {
            chars[0]
        } else {
            chars[rand::rng().random_range(0..chars.len())]
        };

        current_pass = match config.special_char_position.as_str() {
            "start" => format!("{}{}", char_to_add, current_pass),
            "random" => {
                let pos = rand::rng().random_range(0..=current_pass.len());
                let mut new_pass = current_pass;
                new_pass.insert(pos, char_to_add);
                new_pass
            }
            _ => format!("{}{}", current_pass, char_to_add), // "end" is default
        };
        was_modified = true;
    }

    // Uppercase first letter of password
    if config.uppercase_first && !current_pass.is_empty() {
        let first = current_pass.chars().next().unwrap();
        if first.is_ascii_lowercase() {
            current_pass = format!("{}{}", first.to_ascii_uppercase(), &current_pass[1..]);
            was_modified = true;
        }
    }

    if was_modified {
        *modified = true;
    }

    Some(format!("{}:{}", current_user, current_pass))
}

/// Process a large file using streaming I/O
/// Returns the result and calls progress_callback with updates
pub fn apply_transforms_streaming<F>(
    input_path: &Path,
    output_path: &Path,
    config: &TransformConfig,
    mut progress_callback: F,
) -> std::io::Result<TransformResult>
where
    F: FnMut(TransformProgress),
{
    let total_lines = count_lines(input_path)?;
    let mut original_count = 0usize;
    let mut new_count = 0usize;
    let mut modified_count = 0usize;
    let mut duplicates_removed = 0usize;

    // For deduplication, we use hashes instead of full strings to save memory
    let mut seen_hashes: HashSet<u64> = if config.remove_duplicates {
        HashSet::with_capacity(total_lines.min(10_000_000)) // Cap at 10M to prevent OOM
    } else {
        HashSet::new()
    };

    let input_file = File::open(input_path)?;
    let reader = BufReader::with_capacity(1024 * 1024, input_file); // 1MB read buffer

    let output_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file); // 1MB write buffer

    let mut processed = 0usize;
    let mut last_progress_update = 0usize;

    for line_result in reader.lines() {
        let line = line_result?;
        original_count += 1;
        processed += 1;

        // Report progress every 10k lines
        if processed - last_progress_update >= 10_000 {
            last_progress_update = processed;
            progress_callback(TransformProgress {
                phase: "Processing".to_string(),
                processed,
                total: total_lines,
                percent: (processed as f32 / total_lines as f32) * 100.0,
            });
        }

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Check for duplicates using hash
        if config.remove_duplicates {
            let hash = hash_line(&line);
            if !seen_hashes.insert(hash) {
                duplicates_removed += 1;
                continue;
            }
        }

        // Apply transforms
        let mut was_modified = false;
        if let Some(transformed) = transform_line(line, config, &mut was_modified) {
            writeln!(writer, "{}", transformed)?;
            new_count += 1;
            if was_modified {
                modified_count += 1;
            }
        }
    }

    writer.flush()?;

    // Final progress update
    progress_callback(TransformProgress {
        phase: "Complete".to_string(),
        processed: total_lines,
        total: total_lines,
        percent: 100.0,
    });

    Ok(TransformResult {
        original_count,
        new_count,
        removed_count: original_count - new_count,
        modified_count: modified_count + duplicates_removed,
    })
}

/// In-place file transformation for large files
/// Uses a temp file and atomic rename
pub fn apply_transforms_file<F>(
    file_path: &Path,
    config: &TransformConfig,
    progress_callback: F,
) -> std::io::Result<TransformResult>
where
    F: FnMut(TransformProgress),
{
    let temp_path = file_path.with_extension("tmp");

    let result = apply_transforms_streaming(file_path, &temp_path, config, progress_callback)?;

    // Atomic replace: remove original, rename temp to original
    std::fs::remove_file(file_path)?;
    std::fs::rename(&temp_path, file_path)?;

    Ok(result)
}

/// Original in-memory function for backward compatibility (small files)
pub fn apply_transforms(lines: Vec<String>, config: &TransformConfig) -> (Vec<String>, TransformResult) {
    let original_count = lines.len();
    let mut result: Vec<String> = lines;
    let mut modified_count = 0usize;

    // 1. Remove duplicates
    if config.remove_duplicates {
        let before = result.len();
        let mut seen = HashSet::new();
        result.retain(|line| seen.insert(line.clone()));
        let removed = before - result.len();
        if removed > 0 {
            modified_count += removed;
        }
    }

    // 2-4. Filter operations (remove lines based on password criteria)
    result = result.into_iter().filter(|line| {
        if let Some((_, pass)) = split_combo(line) {
            // Length filter
            if config.length_filter_enabled {
                let len = pass.len();
                if len < config.length_min || len > config.length_max {
                    return false;
                }
            }

            // Remove letters-only passwords
            if config.remove_letters_only && is_letters_only(&pass) {
                return false;
            }

            // Remove numbers-only passwords
            if config.remove_numbers_only && is_numbers_only(&pass) {
                return false;
            }

            true
        } else {
            // Keep lines that don't match combo format (or remove them?)
            true
        }
    }).collect();

    // 5. Domain switcher
    if config.domain_switch_enabled && !config.domain_new.is_empty() {
        result = result.into_iter().map(|line| {
            if let Some((user, pass)) = split_combo(&line) {
                let should_switch = if config.domain_switch_all {
                    user.contains('@')
                } else {
                    get_domain(&user).map(|d| d.eq_ignore_ascii_case(&config.domain_old)).unwrap_or(false)
                };

                if should_switch {
                    modified_count += 1;
                    let new_user = replace_domain(&user, &config.domain_new);
                    format!("{}:{}", new_user, pass)
                } else {
                    line
                }
            } else {
                line
            }
        }).collect();
    }

    // 6. Add special character
    if config.special_char_enabled && !config.special_char.is_empty() {
        let chars: Vec<char> = config.special_char.chars().collect();
        result = result.into_iter().map(|line| {
            if let Some((user, pass)) = split_combo(&line) {
                if !has_special_char(&pass) {
                    modified_count += 1;
                    let char_to_add = if chars.len() == 1 {
                        chars[0]
                    } else {
                        chars[rand::rng().random_range(0..chars.len())]
                    };

                    let new_pass = match config.special_char_position.as_str() {
                        "start" => format!("{}{}", char_to_add, pass),
                        "random" => {
                            let pos = rand::rng().random_range(0..=pass.len());
                            let mut new_pass = pass.clone();
                            new_pass.insert(pos, char_to_add);
                            new_pass
                        }
                        _ => format!("{}{}", pass, char_to_add), // "end" is default
                    };
                    format!("{}:{}", user, new_pass)
                } else {
                    line
                }
            } else {
                line
            }
        }).collect();
    }

    // 7. Uppercase first letter of password
    if config.uppercase_first {
        result = result.into_iter().map(|line| {
            if let Some((user, pass)) = split_combo(&line) {
                if !pass.is_empty() {
                    let first = pass.chars().next().unwrap();
                    if first.is_ascii_lowercase() {
                        modified_count += 1;
                        let new_pass = format!("{}{}", first.to_ascii_uppercase(), &pass[1..]);
                        format!("{}:{}", user, new_pass)
                    } else {
                        line
                    }
                } else {
                    line
                }
            } else {
                line
            }
        }).collect();
    }

    let new_count = result.len();
    let removed_count = original_count.saturating_sub(new_count);

    (result, TransformResult {
        original_count,
        new_count,
        removed_count,
        modified_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> TransformConfig {
        TransformConfig {
            length_filter_enabled: false,
            length_min: 0,
            length_max: 100,
            domain_switch_enabled: false,
            domain_switch_all: false,
            domain_old: String::new(),
            domain_new: String::new(),
            special_char_enabled: false,
            special_char: String::new(),
            special_char_position: "end".to_string(),
            uppercase_first: false,
            remove_duplicates: false,
            remove_letters_only: false,
            remove_numbers_only: false,
        }
    }

    #[test]
    fn test_remove_duplicates() {
        let lines = vec![
            "user@test.com:pass123".to_string(),
            "user@test.com:pass123".to_string(),
            "other@test.com:pass456".to_string(),
        ];
        let mut config = default_config();
        config.remove_duplicates = true;

        let (result, stats) = apply_transforms(lines, &config);
        assert_eq!(result.len(), 2);
        assert_eq!(stats.removed_count, 1);
    }

    #[test]
    fn test_length_filter() {
        let lines = vec![
            "user@test.com:ab".to_string(),      // 2 chars - too short
            "user@test.com:password".to_string(), // 8 chars - ok
            "user@test.com:verylongpassword123".to_string(), // too long
        ];
        let mut config = default_config();
        config.length_filter_enabled = true;
        config.length_min = 4;
        config.length_max = 12;

        let (result, _) = apply_transforms(lines, &config);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("password"));
    }

    #[test]
    fn test_remove_letters_only() {
        let lines = vec![
            "user@test.com:password".to_string(),  // letters only - remove
            "user@test.com:pass123".to_string(),   // mixed - keep
        ];
        let mut config = default_config();
        config.remove_letters_only = true;

        let (result, _) = apply_transforms(lines, &config);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("pass123"));
    }

    #[test]
    fn test_domain_switch_all() {
        let lines = vec![
            "user@gmail.com:pass123".to_string(),
            "user@yahoo.com:pass456".to_string(),
        ];
        let mut config = default_config();
        config.domain_switch_enabled = true;
        config.domain_switch_all = true;
        config.domain_new = "newdomain.com".to_string();

        let (result, _) = apply_transforms(lines, &config);
        assert!(result[0].contains("@newdomain.com"));
        assert!(result[1].contains("@newdomain.com"));
    }

    #[test]
    fn test_uppercase_first() {
        let lines = vec![
            "user@test.com:password".to_string(),
            "user@test.com:Password".to_string(), // already uppercase
        ];
        let mut config = default_config();
        config.uppercase_first = true;

        let (result, _) = apply_transforms(lines, &config);
        assert!(result[0].ends_with(":Password"));
        assert!(result[1].ends_with(":Password"));
    }
}
