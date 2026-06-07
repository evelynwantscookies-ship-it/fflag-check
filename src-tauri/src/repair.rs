use serde::Serialize;
use serde_json::Value;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::data::flag_allowlist::is_allowed_flag;
use crate::scanners::client_settings_scanner::should_check_flag_key;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClientSettingsRepairResult {
    pub changed: bool,
    pub removed_flags: Vec<String>,
    pub reset_settings: Vec<String>,
    pub backup_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairError {
    MissingTarget(String),
    TargetNotFile(String),
    UnsupportedTarget(String),
    MissingParent(String),
    ReadFailed(String),
    InvalidJson(String),
    BackupFailed(String),
    WriteFailed(String),
    VerificationFailed(String),
}

impl fmt::Display for RepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepairError::MissingTarget(msg)
            | RepairError::TargetNotFile(msg)
            | RepairError::UnsupportedTarget(msg)
            | RepairError::MissingParent(msg)
            | RepairError::ReadFailed(msg)
            | RepairError::InvalidJson(msg)
            | RepairError::BackupFailed(msg)
            | RepairError::WriteFailed(msg)
            | RepairError::VerificationFailed(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for RepairError {}

#[derive(Default)]
struct RepairChanges {
    removed_flags: Vec<String>,
    reset_settings: Vec<String>,
}

impl RepairChanges {
    fn changed(&self) -> bool {
        !self.removed_flags.is_empty() || !self.reset_settings.is_empty()
    }
}

pub fn repair_client_settings_file(path: &Path) -> Result<ClientSettingsRepairResult, RepairError> {
    validate_repair_target(path)?;

    let original = std::fs::read_to_string(path).map_err(|e| {
        RepairError::ReadFailed(format!(
            "Could not read repair target {}: {}",
            path.display(),
            e
        ))
    })?;
    let mut parsed: Value = serde_json::from_str(&original).map_err(|e| {
        RepairError::InvalidJson(format!(
            "Repair target is not valid JSON: {} ({})",
            path.display(),
            e
        ))
    })?;

    let changes = repair_client_settings_value(&mut parsed);
    if !changes.changed() {
        return Ok(ClientSettingsRepairResult {
            changed: false,
            removed_flags: Vec::new(),
            reset_settings: Vec::new(),
            backup_path: None,
        });
    }

    let backup_path = next_backup_path(path);
    std::fs::write(&backup_path, original.as_bytes()).map_err(|e| {
        RepairError::BackupFailed(format!(
            "Could not write repair backup {}: {}",
            backup_path.display(),
            e
        ))
    })?;

    let rewritten = serde_json::to_string_pretty(&parsed)
        .map(|s| format!("{}\n", s))
        .map_err(|e| {
            RepairError::WriteFailed(format!(
                "Could not serialize repaired JSON for {}: {}",
                path.display(),
                e
            ))
        })?;

    write_repaired_json(path, &backup_path, rewritten.as_bytes())?;
    verify_repaired_file(path)?;

    Ok(ClientSettingsRepairResult {
        changed: true,
        removed_flags: changes.removed_flags,
        reset_settings: changes.reset_settings,
        backup_path: Some(backup_path.display().to_string()),
    })
}

fn validate_repair_target(path: &Path) -> Result<(), RepairError> {
    if !path.exists() {
        return Err(RepairError::MissingTarget(format!(
            "Repair target no longer exists: {}",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(RepairError::TargetNotFile(format!(
            "Repair target is not a file: {}",
            path.display()
        )));
    }
    if !is_supported_repair_file(path) {
        return Err(RepairError::UnsupportedTarget(format!(
            "Prism can only auto-repair known FFlag JSON/config files, not {}",
            path.display()
        )));
    }
    if path.parent().filter(|p| p.is_dir()).is_none() {
        return Err(RepairError::MissingParent(format!(
            "Repair target has no writable parent folder: {}",
            path.display()
        )));
    }
    Ok(())
}

fn is_supported_repair_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower == "clientappsettings.json"
        || lower == "fastflags.json"
        || lower == "fflag.json"
        || lower == "render_cfg.dat"
        || (lower.starts_with("flags_") && lower.ends_with(".json"))
}

fn repair_client_settings_value(value: &mut Value) -> RepairChanges {
    let mut changes = RepairChanges::default();
    let Some(obj) = value.as_object_mut() else {
        return changes;
    };

    let mut bad_flat_keys = obj
        .keys()
        .filter(|key| should_remove_flag_key(key))
        .cloned()
        .collect::<Vec<_>>();
    bad_flat_keys.sort();
    bad_flat_keys.dedup();
    for key in bad_flat_keys {
        if obj.remove(&key).is_some() {
            changes.removed_flags.push(key);
        }
    }

    if let Some(flags) = obj.get_mut("flags").and_then(|v| v.as_array_mut()) {
        let mut removed = Vec::new();
        flags.retain(|entry| {
            let Some(flag) = entry.get("flag").and_then(|v| v.as_str()) else {
                return true;
            };
            let enabled = entry
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if enabled && should_remove_flag_key(flag) {
                removed.push(flag.to_string());
                false
            } else {
                true
            }
        });
        changes.removed_flags.extend(removed);
    }

    reset_bool_setting(obj, "graphics", "unlock_fps", false, &mut changes);
    reset_bool_setting(obj, "visual", "debug_sky", false, &mut changes);
    reset_bool_setting(obj, "utility", "telemetry", true, &mut changes);

    changes.removed_flags.sort();
    changes.removed_flags.dedup();
    changes.reset_settings.sort();
    changes.reset_settings.dedup();
    changes
}

fn should_remove_flag_key(key: &str) -> bool {
    should_check_flag_key(key) && !is_allowed_flag(key)
}

fn reset_bool_setting(
    obj: &mut serde_json::Map<String, Value>,
    group: &str,
    key: &str,
    safe_value: bool,
    changes: &mut RepairChanges,
) {
    let Some(current) = obj
        .get_mut(group)
        .and_then(|v| v.as_object_mut())
        .and_then(|group_obj| group_obj.get_mut(key))
    else {
        return;
    };
    if current.as_bool() == Some(!safe_value) {
        *current = Value::Bool(safe_value);
        changes.reset_settings.push(format!("{}.{}", group, key));
    }
}

fn next_backup_path(path: &Path) -> PathBuf {
    for attempt in 0..1000 {
        let suffix = if attempt == 0 {
            ".prism-backup.json".to_string()
        } else {
            format!(".prism-backup-{}.json", attempt)
        };
        let candidate = PathBuf::from(format!("{}{}", path.display(), suffix));
        if !candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(format!("{}.prism-backup-final.json", path.display()))
}

fn write_repaired_json(path: &Path, backup_path: &Path, content: &[u8]) -> Result<(), RepairError> {
    let tmp_path = PathBuf::from(format!(
        "{}.prism-tmp-{}",
        path.display(),
        std::process::id()
    ));
    std::fs::write(&tmp_path, content).map_err(|e| {
        RepairError::WriteFailed(format!(
            "Could not write temporary repair file {}: {}",
            tmp_path.display(),
            e
        ))
    })?;

    if let Err(first_err) = std::fs::rename(&tmp_path, path) {
        if path.exists() {
            std::fs::remove_file(path).map_err(|remove_err| {
                let _ = std::fs::remove_file(&tmp_path);
                RepairError::WriteFailed(format!(
                    "Could not replace repair target {}: {}; remove failed: {}",
                    path.display(),
                    first_err,
                    remove_err
                ))
            })?;
        }
        if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::copy(backup_path, path);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(RepairError::WriteFailed(format!(
                "Could not replace repair target {}: {}; restored backup if possible",
                path.display(),
                rename_err
            )));
        }
    }

    Ok(())
}

fn verify_repaired_file(path: &Path) -> Result<(), RepairError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        RepairError::VerificationFailed(format!(
            "Could not read repaired file {} for verification: {}",
            path.display(),
            e
        ))
    })?;
    let mut parsed: Value = serde_json::from_str(&content).map_err(|e| {
        RepairError::VerificationFailed(format!(
            "Repaired file is not valid JSON: {} ({})",
            path.display(),
            e
        ))
    })?;
    let remaining = repair_client_settings_value(&mut parsed);
    if remaining.changed() {
        return Err(RepairError::VerificationFailed(format!(
            "Repair verification failed for {}: {} flags/settings remain repairable",
            path.display(),
            remaining.removed_flags.len() + remaining.reset_settings.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "prism-repair-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn repairs_flat_client_settings_and_writes_backup() {
        let dir = tmpdir();
        let path = dir.join("ClientAppSettings.json");
        std::fs::write(
            &path,
            r#"{
              "DFIntS2PhysicsSenderRate": 1,
              "FFlagDebugGraphicsPreferD3D11": true,
              "LauncherTheme": "dark"
            }"#,
        )
        .unwrap();

        let result = repair_client_settings_file(&path).unwrap();
        assert!(result.changed);
        assert_eq!(result.removed_flags, vec!["DFIntS2PhysicsSenderRate"]);
        let backup = result.backup_path.unwrap();
        assert!(Path::new(&backup).exists());

        let repaired: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let obj = repaired.as_object().unwrap();
        assert!(!obj.contains_key("DFIntS2PhysicsSenderRate"));
        assert!(obj.contains_key("FFlagDebugGraphicsPreferD3D11"));
        assert!(obj.contains_key("LauncherTheme"));

        let second = repair_client_settings_file(&path).unwrap();
        assert!(!second.changed);
        assert!(second.backup_path.is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn repairs_appleblox_flags_and_known_boolean_toggles() {
        let dir = tmpdir();
        let path = dir.join("fastflags.json");
        std::fs::write(
            &path,
            r#"{
              "flags": [
                { "flag": "DFIntS2PhysicsSenderRate", "enabled": true, "value": 1 },
                { "flag": "DFFlagAssemblyExtentsExpansionStudHundredth", "enabled": false, "value": -50 },
                { "flag": "FFlagDebugGraphicsPreferD3D11", "enabled": true, "value": true }
              ],
              "graphics": { "unlock_fps": true },
              "visual": { "debug_sky": true },
              "utility": { "telemetry": false }
            }"#,
        )
        .unwrap();

        let result = repair_client_settings_file(&path).unwrap();
        assert_eq!(result.removed_flags, vec!["DFIntS2PhysicsSenderRate"]);
        assert_eq!(
            result.reset_settings,
            vec![
                "graphics.unlock_fps",
                "utility.telemetry",
                "visual.debug_sky"
            ]
        );

        let repaired: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let flags = repaired.get("flags").unwrap().as_array().unwrap();
        assert_eq!(flags.len(), 2);
        assert!(flags.iter().any(|f| {
            f.get("flag").and_then(|v| v.as_str())
                == Some("DFFlagAssemblyExtentsExpansionStudHundredth")
        }));
        assert_eq!(repaired["graphics"]["unlock_fps"].as_bool(), Some(false));
        assert_eq!(repaired["visual"]["debug_sky"].as_bool(), Some(false));
        assert_eq!(repaired["utility"]["telemetry"].as_bool(), Some(true));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn invalid_json_is_not_repaired_or_backed_up() {
        let dir = tmpdir();
        let path = dir.join("ClientAppSettings.json");
        std::fs::write(&path, "{ not json").unwrap();

        let err = repair_client_settings_file(&path).unwrap_err();
        assert!(matches!(err, RepairError::InvalidJson(_)));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
        assert!(!PathBuf::from(format!("{}.prism-backup.json", path.display())).exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn similar_unsupported_json_file_is_not_repaired() {
        let dir = tmpdir();
        let path = dir.join("notes.json");
        std::fs::write(&path, r#"{"DFIntS2PhysicsSenderRate": 1}"#).unwrap();

        let err = repair_client_settings_file(&path).unwrap_err();
        assert!(matches!(err, RepairError::UnsupportedTarget(_)));
        let unchanged: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(unchanged
            .as_object()
            .unwrap()
            .contains_key("DFIntS2PhysicsSenderRate"));
        std::fs::remove_dir_all(dir).ok();
    }
}
