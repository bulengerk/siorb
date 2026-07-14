//! Atomic receipts and append-only transaction journal.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(not(windows))]
use siorb_core::correlation_id;
use siorb_core::{ErrorKind, InstalledPackage, Result, Scope, SiorbError, unix_timestamp};

const STATE_SCHEMA: &str = "1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub schema_version: String,
    pub logical_id: String,
    pub native_id: String,
    pub backend: String,
    pub source_id: String,
    pub requested_version: Option<String>,
    pub observed_version: Option<String>,
    pub scope: Scope,
    pub channel: String,
    pub architecture: String,
    pub catalog_fingerprint: String,
    pub policy_fingerprint: Option<String>,
    pub installed_at_unix: u64,
    pub verification: VerificationRecord,
    pub owned_files: Vec<String>,
    pub transaction_id: String,
    pub origin: ReceiptOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOrigin {
    Installed,
    Adopted,
    Observed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub status: VerificationStatus,
    pub checked_at_unix: u64,
    pub reason: String,
}

/// Stable receipt verification states shared by runtime persistence and the
/// published receipt schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationStatus {
    Verified,
    Failed,
    Unavailable,
    BackendCompleted,
}

impl VerificationStatus {
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalEvent {
    pub schema_version: String,
    pub transaction_id: String,
    pub plan_id: String,
    pub step_id: Option<String>,
    pub timestamp_unix: u64,
    pub state: JournalState,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    TransactionStarted,
    StepStarted,
    StepCompleted,
    StepFailed,
    VerificationCompleted,
    ReceiptCommitted,
    TransactionCompleted,
    TransactionFailed,
    Reconciled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconciliationStatus {
    pub transaction_id: String,
    pub plan_id: String,
    pub last_state: JournalState,
    pub completed_steps: Vec<String>,
    pub failed_steps: Vec<String>,
    pub receipt_committed: bool,
    pub required: bool,
    pub reason_code: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Preferences {
    schema_version: String,
    pins: BTreeMap<String, Option<String>>,
    holds: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct StateStore {
    root: PathBuf,
}

impl StateStore {
    pub fn discover() -> Result<Self> {
        if let Some(path) = env::var_os("SIORB_STATE_DIR") {
            return Self::new(PathBuf::from(path));
        }
        let root = if cfg!(windows) {
            env::var_os("LOCALAPPDATA").map(PathBuf::from)
        } else if cfg!(target_os = "macos") {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|path| path.join("Library/Application Support"))
        } else {
            env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|path| path.join(".local/share"))
            })
        }
        .ok_or_else(|| {
            state_error(
                "state.directory.unavailable",
                "cannot determine the platform application-data directory".to_owned(),
            )
        })?;
        Self::new(root.join("siorb"))
    }

    pub fn new(root: PathBuf) -> Result<Self> {
        let store = Self { root };
        store.ensure_layout()?;
        Ok(store)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_receipt(&self, receipt: &Receipt) -> Result<()> {
        validate_component(&receipt.logical_id)?;
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.root.join("receipts"))?;
        let path = self.receipt_path(&receipt.logical_id);
        ensure_regular_file_or_missing(&path)?;
        atomic_json_write(&path, receipt)
    }

    pub fn remove_receipt(&self, logical_id: &str) -> Result<()> {
        validate_component(logical_id)?;
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.root.join("receipts"))?;
        let path = self.receipt_path(logical_id);
        if fs::symlink_metadata(&path).is_ok() {
            ensure_regular_file_or_missing(&path)?;
            fs::remove_file(&path).map_err(|error| {
                state_error(
                    "state.receipt.remove",
                    format!("cannot remove receipt {}: {error}", path.display()),
                )
            })?;
        }
        Ok(())
    }

    pub fn receipts(&self) -> Result<Vec<Receipt>> {
        let directory = self.root.join("receipts");
        validate_private_directory(&self.root)?;
        validate_private_directory(&directory)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&directory)
            .map_err(|error| state_error("state.receipt.list", error.to_string()))?
        {
            let entry =
                entry.map_err(|error| state_error("state.receipt.inspect", error.to_string()))?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| state_error("state.receipt.inspect", error.to_string()))?;
            if kind.is_symlink() || !kind.is_file() {
                return Err(state_error(
                    "state.receipt.file_type",
                    format!("receipt {} is not a regular file", path.display()),
                ));
            }
            paths.push(path);
        }
        paths.sort();
        paths.into_iter().map(|path| read_json(&path)).collect()
    }

    pub fn installed_snapshot(&self) -> Result<Vec<InstalledPackage>> {
        let preferences = self.preferences()?;
        self.receipts().map(|receipts| {
            receipts
                .into_iter()
                .map(|receipt| InstalledPackage {
                    logical_id: receipt.logical_id.clone(),
                    native_id: receipt.native_id,
                    backend: receipt.backend,
                    version: receipt.observed_version,
                    scope: receipt.scope,
                    receipt: true,
                    held: preferences.holds.contains(&receipt.logical_id),
                    pinned: preferences.pins.get(&receipt.logical_id).cloned().flatten(),
                })
                .collect()
        })
    }

    pub fn append_event(&self, event: &JournalEvent) -> Result<()> {
        validate_component(&event.transaction_id)?;
        validate_private_directory(&self.root)?;
        let path = self.root.join("journal.ndjson");
        ensure_regular_file_or_missing(&path)?;
        let mut file = open_append_nofollow(&path)
            .map_err(|error| state_error("state.journal.open", error.to_string()))?;
        validate_open_private_file(&file, &path)?;
        let encoded = serde_json::to_string(event)
            .map_err(|error| state_error("state.journal.encode", error.to_string()))?;
        file.write_all(encoded.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_data())
            .map_err(|error| state_error("state.journal.write", error.to_string()))
    }

    pub fn journal(&self) -> Result<Vec<JournalEvent>> {
        let path = self.root.join("journal.ndjson");
        validate_private_directory(&self.root)?;
        if fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(Vec::new());
        }
        ensure_regular_file_or_missing(&path)?;
        let file = open_readonly_nofollow(&path)
            .map_err(|error| state_error("state.journal.open", error.to_string()))?;
        validate_open_private_file(&file, &path)?;
        let reader = BufReader::new(file);
        reader
            .lines()
            .enumerate()
            .map(|(index, line)| {
                let line =
                    line.map_err(|error| state_error("state.journal.read", error.to_string()))?;
                serde_json::from_str(&line).map_err(|error| {
                    state_error(
                        "state.journal.corrupt",
                        format!("journal line {} is invalid: {error}", index + 1),
                    )
                })
            })
            .collect()
    }

    pub fn unfinished_transactions(&self) -> Result<Vec<String>> {
        Ok(self
            .transactions_requiring_reconciliation()?
            .into_iter()
            .map(|status| status.transaction_id)
            .collect())
    }

    /// Summarize every journal transaction and retain failed transactions when
    /// at least one step or receipt was committed. A terminal error is not the
    /// same thing as a reconciled partial mutation.
    pub fn reconciliation_statuses(&self) -> Result<Vec<ReconciliationStatus>> {
        #[derive(Default)]
        struct Accumulator {
            plan_id: String,
            last_state: Option<JournalState>,
            completed: BTreeSet<String>,
            failed: BTreeSet<String>,
            receipt_committed: bool,
        }

        let mut transactions: BTreeMap<String, Accumulator> = BTreeMap::new();
        for event in self.journal()? {
            let entry = transactions.entry(event.transaction_id).or_default();
            entry.plan_id = event.plan_id;
            entry.last_state = Some(event.state);
            match event.state {
                JournalState::StepCompleted => {
                    if let Some(step) = event.step_id {
                        entry.completed.insert(step);
                    }
                }
                JournalState::StepFailed => {
                    if let Some(step) = event.step_id {
                        entry.failed.insert(step);
                    }
                }
                JournalState::ReceiptCommitted => entry.receipt_committed = true,
                _ => {}
            }
        }
        Ok(transactions
            .into_iter()
            .filter_map(|(transaction_id, accumulated)| {
                let last_state = accumulated.last_state?;
                let partial_mutation =
                    accumulated.receipt_committed || !accumulated.completed.is_empty();
                let (required, reason_code) = match last_state {
                    JournalState::TransactionCompleted | JournalState::Reconciled => {
                        (false, "state.transaction.terminal")
                    }
                    JournalState::TransactionFailed if partial_mutation => {
                        (true, "state.transaction.partial_failure")
                    }
                    JournalState::TransactionFailed => {
                        (false, "state.transaction.failed_without_mutation")
                    }
                    _ => (true, "state.transaction.interrupted"),
                };
                Some(ReconciliationStatus {
                    transaction_id,
                    plan_id: accumulated.plan_id,
                    last_state,
                    completed_steps: accumulated.completed.into_iter().collect(),
                    failed_steps: accumulated.failed.into_iter().collect(),
                    receipt_committed: accumulated.receipt_committed,
                    required,
                    reason_code: reason_code.to_owned(),
                })
            })
            .collect())
    }

    pub fn transactions_requiring_reconciliation(&self) -> Result<Vec<ReconciliationStatus>> {
        Ok(self
            .reconciliation_statuses()?
            .into_iter()
            .filter(|status| status.required)
            .collect())
    }

    pub fn mark_reconciled(&self, transaction_id: &str, detail: &str) -> Result<()> {
        validate_component(transaction_id)?;
        let status = self
            .transactions_requiring_reconciliation()?
            .into_iter()
            .find(|status| status.transaction_id == transaction_id)
            .ok_or_else(|| {
                state_error(
                    "state.reconcile.not_required",
                    format!("transaction `{transaction_id}` does not require reconciliation"),
                )
            })?;
        self.append_event(&JournalEvent {
            schema_version: STATE_SCHEMA.to_owned(),
            transaction_id: transaction_id.to_owned(),
            plan_id: status.plan_id,
            step_id: None,
            timestamp_unix: unix_timestamp(),
            state: JournalState::Reconciled,
            detail: detail.to_owned(),
        })
    }

    pub fn pin(&self, package: &str, version: Option<String>) -> Result<()> {
        validate_component(package)?;
        let mut preferences = self.preferences()?;
        preferences.pins.insert(package.to_owned(), version);
        self.write_preferences(&preferences)
    }

    pub fn unpin(&self, package: &str) -> Result<bool> {
        let mut preferences = self.preferences()?;
        let removed = preferences.pins.remove(package).is_some();
        self.write_preferences(&preferences)?;
        Ok(removed)
    }

    pub fn hold(&self, package: &str) -> Result<()> {
        validate_component(package)?;
        let mut preferences = self.preferences()?;
        preferences.holds.insert(package.to_owned());
        self.write_preferences(&preferences)
    }

    pub fn unhold(&self, package: &str) -> Result<bool> {
        let mut preferences = self.preferences()?;
        let removed = preferences.holds.remove(package);
        self.write_preferences(&preferences)?;
        Ok(removed)
    }

    pub fn clear_diagnostics(&self) -> Result<()> {
        let diagnostics = self.root.join("diagnostics");
        validate_private_directory(&self.root)?;
        match fs::symlink_metadata(&diagnostics) {
            Ok(_) => {
                validate_private_directory(&diagnostics)?;
                fs::remove_dir_all(&diagnostics)
                    .map_err(|error| state_error("state.diagnostics.remove", error.to_string()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(state_error("state.directory.inspect", error.to_string()));
            }
        }
        create_private_dir(&diagnostics)
    }

    fn receipt_path(&self, logical_id: &str) -> PathBuf {
        self.root
            .join("receipts")
            .join(format!("{logical_id}.json"))
    }

    fn preferences(&self) -> Result<Preferences> {
        validate_private_directory(&self.root)?;
        let path = self.root.join("preferences.json");
        if !path.exists() {
            return Ok(Preferences {
                schema_version: STATE_SCHEMA.to_owned(),
                ..Preferences::default()
            });
        }
        read_json(&path)
    }

    fn write_preferences(&self, preferences: &Preferences) -> Result<()> {
        validate_private_directory(&self.root)?;
        atomic_json_write(&self.root.join("preferences.json"), preferences)
    }

    fn ensure_layout(&self) -> Result<()> {
        create_private_dir(&self.root)?;
        create_private_dir(&self.root.join("receipts"))?;
        create_private_dir(&self.root.join("cache"))?;
        create_private_dir(&self.root.join("diagnostics"))
    }
}

fn validate_component(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-._".contains(character))
    {
        return Err(state_error(
            "state.identifier.unsafe",
            format!("`{value}` is unsafe for local state"),
        ));
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    fs::create_dir_all(path)
        .map_err(|error| state_error("state.directory.create", error.to_string()))?;
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state_error("state.directory.inspect", error.to_string()))?;
    if !metadata.file_type().is_dir() {
        return Err(state_error(
            "state.directory.file_type",
            format!("{} is not a regular directory", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        validate_unix_owner(&metadata, path, effective_uid())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| state_error("state.directory.permissions", error.to_string()))?;
    }
    validate_private_directory(path)
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(state_error("state.path.inspect", error.to_string())),
        };
        #[cfg(not(windows))]
        let is_link = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let is_link = windows_metadata_is_reparse_point(&metadata);
        if is_link {
            return Err(state_error(
                "state.path.symlink",
                format!(
                    "state path component {} is a symbolic link or reparse point",
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| state_error("state.directory.inspect", error.to_string()))?;
    if !metadata.file_type().is_dir() {
        return Err(state_error(
            "state.directory.file_type",
            format!("{} is not a regular directory", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        validate_unix_owner(&metadata, path, effective_uid())?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(state_error(
                "state.directory.permissions",
                format!("{} is accessible by another user", path.display()),
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_path_security(path)?;
    Ok(())
}

fn ensure_regular_file_or_missing(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(state_error("state.file.inspect", error.to_string())),
    };
    #[cfg(not(windows))]
    let linked = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let linked = windows_metadata_is_reparse_point(&metadata);
    if linked || !metadata.file_type().is_file() {
        return Err(state_error(
            "state.file.type",
            format!("{} is not a regular non-link file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        validate_unix_owner(&metadata, path, effective_uid())?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(state_error(
                "state.file.permissions",
                format!("{} is accessible by another user", path.display()),
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_path_security(path)?;
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn validate_unix_owner(metadata: &fs::Metadata, path: &Path, expected_uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != expected_uid {
        return Err(state_error(
            "state.permissions.wrong_owner",
            format!(
                "{} is owned by uid {}, expected effective uid {expected_uid}",
                path.display(),
                metadata.uid()
            ),
        ));
    }
    Ok(())
}

fn validate_open_private_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| state_error("state.file.inspect", error.to_string()))?;
    #[cfg(windows)]
    let linked = windows_metadata_is_reparse_point(&metadata);
    #[cfg(not(windows))]
    let linked = metadata.file_type().is_symlink();
    if linked || !metadata.file_type().is_file() {
        return Err(state_error(
            "state.file.type",
            format!("{} is not a regular non-link file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        validate_unix_owner(&metadata, path, effective_uid())?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(state_error(
                "state.file.permissions",
                format!("{} is accessible by another user", path.display()),
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_handle_security(file, path)?;
    Ok(())
}

#[cfg(windows)]
fn windows_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn validate_windows_path_security(path: &Path) -> Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};

    let descriptor = windows_permissions::wrappers::GetNamedSecurityInfo(
        path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|error| windows_security_unavailable(path, &error))?;
    validate_windows_security_descriptor(&descriptor, path)
}

#[cfg(windows)]
fn validate_windows_handle_security(file: &File, path: &Path) -> Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};

    let descriptor = windows_permissions::wrappers::GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|error| windows_security_unavailable(path, &error))?;
    validate_windows_security_descriptor(&descriptor, path)
}

#[cfg(windows)]
fn validate_windows_security_descriptor(
    descriptor: &windows_permissions::SecurityDescriptor,
    path: &Path,
) -> Result<()> {
    use windows_permissions::constants::{AccessRights, AceType};
    use windows_permissions::{LocalBox, Sid, Trustee};

    let current = windows_permissions::utilities::current_process_sid()
        .map_err(|error| windows_security_unavailable(path, &error))?;
    let owner = descriptor.owner().ok_or_else(|| {
        state_error(
            "state.permissions.ownership_unavailable",
            format!("cannot establish an owner for {}", path.display()),
        )
    })?;
    if owner != current.as_ref() {
        return Err(state_error(
            "state.permissions.wrong_owner",
            format!(
                "{} is owned by SID {owner}, expected current process SID {}",
                path.display(),
                current.as_ref()
            ),
        ));
    }

    let dacl = descriptor.dacl().ok_or_else(|| {
        state_error(
            "state.permissions.too_open",
            format!(
                "{} has no discretionary access-control list",
                path.display()
            ),
        )
    })?;
    let system = "S-1-5-18".parse::<LocalBox<Sid>>().map_err(|error| {
        state_error(
            "state.permissions.acl_unavailable",
            format!("cannot construct the LocalSystem SID: {error}"),
        )
    })?;
    let administrators = "S-1-5-32-544".parse::<LocalBox<Sid>>().map_err(|error| {
        state_error(
            "state.permissions.acl_unavailable",
            format!("cannot construct the Administrators SID: {error}"),
        )
    })?;

    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or_else(|| {
            state_error(
                "state.permissions.acl_unavailable",
                format!("cannot inspect ACL entry {index} for {}", path.display()),
            )
        })?;
        let grants_access = matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) && !ace.mask().is_empty();
        if !grants_access {
            continue;
        }
        let trustee = ace.sid().ok_or_else(|| {
            state_error(
                "state.permissions.acl_unavailable",
                format!(
                    "cannot establish the SID for ACL entry {index} on {}",
                    path.display()
                ),
            )
        })?;
        if trustee != current.as_ref()
            && trustee != system.as_ref()
            && trustee != administrators.as_ref()
        {
            return Err(state_error(
                "state.permissions.too_open",
                format!(
                    "{} grants access to untrusted SID {trustee}",
                    path.display()
                ),
            ));
        }
    }

    let current_trustee: Trustee = current.as_ref().into();
    let rights = dacl.effective_rights(&current_trustee).map_err(|error| {
        state_error(
            "state.permissions.acl_unavailable",
            format!(
                "cannot evaluate current-user access to {}: {error}",
                path.display()
            ),
        )
    })?;
    let can_read_and_write = rights.contains(AccessRights::FileAllAccess)
        || rights.contains(AccessRights::GenericAll)
        || (rights.contains(AccessRights::FileGenericRead)
            && rights.contains(AccessRights::FileGenericWrite))
        || (rights.contains(AccessRights::GenericRead)
            && rights.contains(AccessRights::GenericWrite));
    if !can_read_and_write {
        return Err(state_error(
            "state.permissions.access_denied",
            format!(
                "the current process SID lacks private read/write access to {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_security_unavailable(path: &Path, error: &std::io::Error) -> SiorbError {
    state_error(
        "state.permissions.ownership_unavailable",
        format!(
            "cannot query the owner and access controls for {}: {error}",
            path.display()
        ),
    )
}

fn open_append_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn open_readonly_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn atomic_json_write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        state_error(
            "state.directory.inspect",
            format!("{} has no state directory", path.display()),
        )
    })?;
    validate_private_directory(parent)?;
    ensure_regular_file_or_missing(path)?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| state_error("state.encode", error.to_string()))?;
    #[cfg(windows)]
    {
        use atomicwrites::{AllowOverwrite, AtomicFile};

        AtomicFile::new(path, AllowOverwrite)
            .write(|file| {
                file.write_all(&bytes)?;
                file.write_all(b"\n")?;
                file.sync_all()
            })
            .map_err(|error| {
                let error: std::io::Error = error.into();
                state_error("state.atomic.replace", error.to_string())
            })?;
        ensure_regular_file_or_missing(path)
    }
    #[cfg(not(windows))]
    {
        let temporary = path.with_extension(format!("tmp-{}", correlation_id()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| state_error("state.temporary.create", error.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|error| state_error("state.file.permissions", error.to_string()))?;
            }
            validate_open_private_file(&file, &temporary)?;
            file.write_all(&bytes)
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.sync_all())
                .map_err(|error| state_error("state.temporary.write", error.to_string()))?;
        }
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(state_error("state.atomic.rename", error.to_string()));
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| state_error("state.directory.sync", error.to_string()))?;
        ensure_regular_file_or_missing(path)
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    ensure_regular_file_or_missing(path)?;
    let mut file = open_readonly_nofollow(path)
        .map_err(|error| state_error("state.read", error.to_string()))?;
    validate_open_private_file(&file, path)?;
    let metadata = file
        .metadata()
        .map_err(|error| state_error("state.read", error.to_string()))?;
    if metadata.len() > 16 * 1024 * 1024 {
        return Err(state_error(
            "state.read.size",
            format!("{} exceeds the state file size boundary", path.display()),
        ));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        state_error(
            "state.read.size",
            format!(
                "{} cannot fit in this process address space",
                path.display()
            ),
        )
    })?;
    let mut input = Vec::with_capacity(capacity);
    file.read_to_end(&mut input)
        .map_err(|error| state_error("state.read", error.to_string()))?;
    serde_json::from_slice(&input).map_err(|error| {
        state_error(
            "state.corrupt",
            format!("state file {} is corrupt: {error}", path.display()),
        )
    })
}

fn state_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::VerificationFailure,
        message,
        "Inspect the state file, restore a known-good copy, or run `siorb reconcile`.",
    )
    .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn receipt_round_trip_and_unfinished_detection() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let store = StateStore::new(directory.path().to_path_buf());
        assert!(store.is_ok());
        let Some(store) = store.ok() else { return };
        let receipt = Receipt {
            schema_version: STATE_SCHEMA.to_owned(),
            logical_id: "firefox".to_owned(),
            native_id: "firefox".to_owned(),
            backend: "apt".to_owned(),
            source_id: "firefox-apt".to_owned(),
            requested_version: None,
            observed_version: Some("1".to_owned()),
            scope: Scope::System,
            channel: "stable".to_owned(),
            architecture: "x86_64".to_owned(),
            catalog_fingerprint: "a".repeat(64),
            policy_fingerprint: None,
            installed_at_unix: 1,
            verification: VerificationRecord {
                status: VerificationStatus::Verified,
                checked_at_unix: 1,
                reason: "backend-query".to_owned(),
            },
            owned_files: vec![],
            transaction_id: "tx-1".to_owned(),
            origin: ReceiptOrigin::Installed,
        };
        assert!(store.write_receipt(&receipt).is_ok());
        assert_eq!(store.receipts().ok().map(|values| values.len()), Some(1));
        let event = JournalEvent {
            schema_version: STATE_SCHEMA.to_owned(),
            transaction_id: "tx-1".to_owned(),
            plan_id: "plan-1".to_owned(),
            step_id: None,
            timestamp_unix: 1,
            state: JournalState::TransactionStarted,
            detail: String::new(),
        };
        assert!(store.append_event(&event).is_ok());
        assert_eq!(
            store.unfinished_transactions().ok(),
            Some(vec!["tx-1".to_owned()])
        );
    }

    #[test]
    fn traversal_component_is_rejected() {
        assert!(validate_component("../receipt").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_owner_mismatch_uses_the_stable_fixture_reason() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let path = directory.path().join("state.json");
        assert!(fs::write(&path, b"{}").is_ok());
        assert!(fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).is_ok());
        let metadata = fs::symlink_metadata(&path);
        assert!(metadata.is_ok());
        let Some(metadata) = metadata.ok() else {
            return;
        };
        assert!(validate_unix_owner(&metadata, &path, metadata.uid()).is_ok());

        let error = validate_unix_owner(&metadata, &path, metadata.uid() ^ 1);
        assert_eq!(
            error.err().map(|error| error.reason_code).as_deref(),
            Some("state.permissions.wrong_owner")
        );
    }

    #[test]
    fn failed_partial_transaction_requires_explicit_reconciliation() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let store = StateStore::new(directory.path().to_path_buf());
        assert!(store.is_ok());
        let Some(store) = store.ok() else { return };
        for (step_id, state) in [
            (None, JournalState::TransactionStarted),
            (Some("step-1"), JournalState::StepCompleted),
            (Some("step-2"), JournalState::StepFailed),
            (None, JournalState::TransactionFailed),
        ] {
            assert!(
                store
                    .append_event(&JournalEvent {
                        schema_version: STATE_SCHEMA.to_owned(),
                        transaction_id: "tx-partial".to_owned(),
                        plan_id: "plan-1".to_owned(),
                        step_id: step_id.map(str::to_owned),
                        timestamp_unix: 1,
                        state,
                        detail: String::new(),
                    })
                    .is_ok()
            );
        }
        let statuses = store.transactions_requiring_reconciliation();
        assert!(statuses.is_ok());
        let Some(statuses) = statuses.ok() else {
            return;
        };
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].reason_code, "state.transaction.partial_failure");
        assert!(
            store
                .mark_reconciled("tx-partial", "verified current backend state")
                .is_ok()
        );
        assert!(
            store
                .unfinished_transactions()
                .is_ok_and(|values| values.is_empty())
        );
    }

    #[cfg(unix)]
    #[test]
    fn swapped_receipt_and_journal_links_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let store = StateStore::new(directory.path().join("state"));
        assert!(store.is_ok());
        let Some(store) = store.ok() else { return };

        let outside = directory.path().join("outside");
        assert!(fs::write(&outside, b"unchanged").is_ok());
        let receipt_link = store.root().join("receipts/linked.json");
        assert!(symlink(&outside, &receipt_link).is_ok());
        assert!(store.receipts().is_err());
        assert!(fs::remove_file(&receipt_link).is_ok());

        let journal_link = store.root().join("journal.ndjson");
        assert!(symlink(&outside, &journal_link).is_ok());
        let event = JournalEvent {
            schema_version: STATE_SCHEMA.to_owned(),
            transaction_id: "tx-link".to_owned(),
            plan_id: "plan-link".to_owned(),
            step_id: None,
            timestamp_unix: 1,
            state: JournalState::TransactionStarted,
            detail: String::new(),
        };
        assert!(store.append_event(&event).is_err());
        assert_eq!(
            fs::read(&outside).ok().as_deref(),
            Some(b"unchanged".as_slice())
        );
    }
}
