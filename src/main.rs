use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Nonce, Key,
};
use rustyline::{
    completion::{Completer, Pair},
    error::ReadlineError,
    Editor, Config, CompletionType, EditMode,
    Helper,
    validate::Validator,
    highlight::Highlighter,
    hint::Hinter,
    history::DefaultHistory,
};
use arboard::Clipboard;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux;
use base32::{Alphabet, decode};
use chrono::Utc;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as HmacKeyInit;
use serde::{Deserialize, Serialize};
use rpassword::read_password;
use sha2::{Digest, Sha256, Sha512};
use argon2::{Argon2, Params, Version, Algorithm as ArgonAlgorithm};
use directories::ProjectDirs;
use zeroize::{Zeroizing, Zeroize};
use thiserror::Error;
use url::Url;
use urlencoding::decode as url_decode;
use urlencoding::encode;


#[derive(Debug, Error)]
enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Argon2 parameter error: {0}")]
    Argon2Params(String),
    #[error("Argon2 encryption error: {0}")]
    Argon2Hash(String),
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("AES encryption/decryption error")]
    Crypto,
    #[error("Data serialization/deserialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid data format: {0}")]
    InvalidData(String),
    #[error("The transaction was canceled by the user: {0}")]
    Cancelled(String),
    #[error("Clipboard error: {0}")]
    Clipboard(String),
    #[error("Readline error: {0}")]
    Readline(String),
}

struct AccountCompleter {
    accounts: Vec<String>,
}

impl Completer for AccountCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        _pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let input = line.trim().to_lowercase();
        
        if input.is_empty() {
            return Ok((0, vec![]));
        }

        let mut suggestions: Vec<(String, usize)> = self
            .accounts
            .iter()
            .filter_map(|name| {
                let name_lower = name.to_lowercase();
                
                if name_lower.starts_with(&input) {
                    return Some((name.clone(), 0));
                }
                
                for word in name_lower.split(|c: char| c == ' ' || c == '-' || c == '_' || c == ':') {
                    if !word.is_empty() && word.starts_with(&input) {
                        return Some((name.clone(), 1));
                    }
                }
                
                None
            })
            .collect();

        suggestions.sort_by(|(name_a, priority_a), (name_b, priority_b)| {
            priority_a.cmp(priority_b)
                .then_with(|| name_a.to_lowercase().cmp(&name_b.to_lowercase()))
        });
        
        suggestions.truncate(10);

        let completions = suggestions
            .into_iter()
            .map(|(name, _)| Pair {
                display: name.clone(),
                replacement: name,
            })
            .collect();

        Ok((0, completions))
    }
}

impl Helper for AccountCompleter {}
impl Validator for AccountCompleter {}
impl Highlighter for AccountCompleter {}
impl Hinter for AccountCompleter {
    type Hint = String;
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AppError::Argon2Hash(err.to_string())
    }
}
impl From<argon2::Error> for AppError {
    fn from(err: argon2::Error) -> Self {
        AppError::Argon2(err.to_string())
    }
}
impl From<arboard::Error> for AppError {
    fn from(err: arboard::Error) -> Self {
        AppError::Clipboard(err.to_string())
    }
}
impl From<ReadlineError> for AppError {
    fn from(err: ReadlineError) -> Self {
        AppError::Readline(err.to_string())
    }
}
type AppResult<T> = Result<T, AppError>;
type HmacSha1 = Hmac<sha1::Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
enum OtpType {
    Totp,
    Hotp,
}
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OtpEntry {
    secret: Zeroizing<String>,
    otp_type: OtpType,
    algorithm: OtpAlgorithm,
    digits: u8,
    step: u64,
    counter: u64,
    #[serde(default)]
    note: Zeroizing<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AppSettings {
    #[serde(default)]
    auto_copy_to_clipboard: bool,
    hide_otp_codes: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            auto_copy_to_clipboard: false,
            hide_otp_codes: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct StoredData {
    entries: HashMap<String, OtpEntry>,
    salt: Vec<u8>,
    #[serde(default)]
    settings: AppSettings,
}

const ARGON2_TIME: u32 = 3;
const ARGON2_MEMORY: u32 = 131072;
const ARGON2_PARALLELISM: u32 = 4;
const STORE_FILE_BASE: &str = "auth_store";

fn get_project_dirs() -> AppResult<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("com", "YourOrg", "KriptonAuthenticator") {
        let data_dir = proj_dirs.data_dir();
        fs::create_dir_all(data_dir)?;
        Ok(data_dir.to_path_buf())
    } else {
        Err(AppError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not find a valid home directory.",
        )))
    }
}

fn read_account_name(
    prompt: &str,
    entries: &HashMap<String, OtpEntry>,
) -> AppResult<Zeroizing<String>> {
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();
    let mut rl = Editor::<AccountCompleter, DefaultHistory>::with_config(config)?;
    rl.set_helper(Some(AccountCompleter {
        accounts: entries.keys().cloned().collect(),
    }));

    let input = rl.readline(prompt)?;
    let trimmed = Zeroizing::new(input.trim().to_string());
    Ok(trimmed)
}

fn store_path_for_password(password: &str) -> AppResult<PathBuf> {
    let data_dir = get_project_dirs()?;
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hex_digest = format!("{:x}", result);
    let prefix = &hex_digest[..8];
    let file_name = format!("{}_{}.enc", STORE_FILE_BASE, prefix);

    Ok(data_dir.join(file_name))
}

fn secure_delete(path: &Path) -> AppResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let file_size = fs::metadata(path)?.len();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)?;
    let mut buffer = vec![0u8; 4096];
    let mut bytes_written = 0;
    while bytes_written < file_size {
        let remaining = file_size - bytes_written;
        let chunk_size = std::cmp::min(buffer.len() as u64, remaining) as usize;
        OsRng.fill_bytes(&mut buffer[..chunk_size]);
        file.write_all(&buffer[..chunk_size])?;
        bytes_written += chunk_size as u64;
    }
    file.sync_data()?;
    let _ = file.set_len(0);
    let _ = file.sync_data();
    fs::remove_file(path)?;
    Ok(())
}

fn change_master_password(
    old_password: &Zeroizing<String>,
    store: &mut StoredData,
) -> AppResult<Zeroizing<String>> {
    println!("\n=== Master Password Change ===");
    print!("Enter NEW password: ");
    io::stdout().flush()?;
    let new_pass1 = Zeroizing::new(read_password()?);
    print!("Re-enter NEW password: ");
    io::stdout().flush()?;
    let new_pass2 = Zeroizing::new(read_password()?);

    let trimmed_new_pass1 = Zeroizing::new(new_pass1.trim().to_string());
    let trimmed_new_pass2 = Zeroizing::new(new_pass2.trim().to_string());
    if trimmed_new_pass1.as_str().is_empty() {
        return Err(AppError::Cancelled("Password cannot be empty.".to_string()));
    }
    if trimmed_new_pass1.as_str() != trimmed_new_pass2.as_str() {
        println!("Passwords do not match. Operation cancelled.");
        return Err(AppError::Cancelled(
            "New passwords do not match.".to_string(),
        ));
    }

    let old_path = store_path_for_password(old_password)?;
    let new_path = store_path_for_password(&trimmed_new_pass1)?;

    if new_path.exists() {
        print!(
            "A store file for the NEW password already exists ({}). Overwrite? (Y/N): ",
            new_path.display()
        );
        io::stdout().flush()?;
        let mut answer = Zeroizing::new(String::new());
        io::stdin().read_line(&mut *answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            return Err(AppError::Cancelled(
                "Operation cancelled by user.".to_string(),
            ));
        }
        let _ = fs::remove_file(&new_path);
    }

    let mut new_salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut new_salt);
    store.salt = new_salt.to_vec();
    encrypt_store(&new_path, &trimmed_new_pass1, store)?;

    if old_path.exists() {
        secure_delete(&old_path)?;
        println!("\nMaster password changed successfully. Old store file securely deleted.");
    } else {
        println!("\nMaster password changed successfully. (No previous file to delete).");
    }

    Ok(trimmed_new_pass1)
}

fn parse_otpauth_uri(uri_str: &str) -> Result<(Zeroizing<String>, OtpEntry), String> {
    let uri = Url::parse(uri_str).map_err(|e| format!("Invalid URI format: {}", e))?;

    if uri.scheme() != "otpauth" {
        return Err("Not an otpauth URI".to_string());
    }

    let otp_type = match uri.host_str() {
        Some("totp") => OtpType::Totp,
        Some("hotp") => OtpType::Hotp,
        _ => return Err("Invalid or missing OTP type (totp/hotp)".to_string()),
    };

    let path = uri.path().trim_start_matches('/');
    let (issuer_from_label, name_from_label) = if let Some(colon_pos) = path.find(':') {
        let (issuer, name) = path.split_at(colon_pos);
        (
            Some(
                url_decode(issuer)
                    .map_err(|e| e.to_string())?
                    .into_owned(),
            ),
            url_decode(&name[1..])
                .map_err(|e| e.to_string())?
                .into_owned(),
        )
    } else {
        (
            None,
            url_decode(path)
                .map_err(|e| e.to_string())?
                .into_owned(),
        )
    };

    let params: HashMap<String, String> = uri.query_pairs().into_owned().collect();

    let secret = Zeroizing::new(
        params
            .get("secret")
            .ok_or("Secret parameter is missing")?
            .to_string(),
    );

    if validate_base32(&secret).is_err() {
        return Err("Invalid Base32 secret".to_string());
    }

    let final_name = Zeroizing::new(if let Some(issuer_param) = params.get("issuer") {
        format!("{}:{}", issuer_param, name_from_label)
    } else if let Some(issuer) = issuer_from_label {
        format!("{}:{}", issuer, name_from_label)
    } else {
        name_from_label
    });

    let algorithm = match params.get("algorithm").map(|s| s.to_uppercase()) {
        Some(s) if s == "SHA256" => OtpAlgorithm::Sha256,
        Some(s) if s == "SHA512" => OtpAlgorithm::Sha512,
        _ => OtpAlgorithm::Sha1,
    };

    let digits = match params.get("digits").and_then(|s| s.parse::<u8>().ok()) {
        Some(8) => 8,
        _ => 6,
    };

    let mut entry = OtpEntry {
        secret,
        otp_type,
        algorithm,
        digits,
        step: 0,
        counter: 0,
        note: Zeroizing::new(String::new()),
    };

    match otp_type {
        OtpType::Totp => {
            entry.step = match params.get("period").and_then(|s| s.parse::<u64>().ok()) {
                Some(p) if p > 0 => p,
                _ => 30,
            };
        }
        OtpType::Hotp => {
            entry.counter = params
                .get("counter")
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or("HOTP entry is missing counter parameter")?;
        }
    }

    Ok((final_name, entry))
}

fn any_store_files_exist() -> AppResult<bool> {
    let data_dir = match get_project_dirs() {
        Ok(dir) => dir,
        Err(AppError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    if !data_dir.exists() {
        return Ok(false);
    }

    for entry in fs::read_dir(data_dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with(&format!("{}_", STORE_FILE_BASE)) && name.ends_with(".enc") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn derive_key(password: &str, salt: &[u8]) -> AppResult<Zeroizing<[u8; KEY_SIZE]>> {
    let params = Params::new(ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARALLELISM, Some(KEY_SIZE))
        .map_err(|e| AppError::Argon2Params(e.to_string()))?;
    let argon2 = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE]);
    argon2.hash_password_into(password.as_bytes(), salt, &mut *key_bytes)?;
    Ok(key_bytes)
}

fn core_encrypt(
    key: &Zeroizing<[u8; KEY_SIZE]>,
    nonce: &[u8; NONCE_SIZE],
    data: &[u8],
) -> AppResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&**key));
    let nonce_array = Nonce::from_slice(nonce);
    cipher.encrypt(nonce_array, data).map_err(|_| AppError::Crypto)
}

fn core_decrypt(
    key: &Zeroizing<[u8; KEY_SIZE]>,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> AppResult<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&**key));
    let nonce_array = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce_array, ciphertext)
        .map_err(|_| AppError::Crypto)?;
    Ok(Zeroizing::new(plaintext))
}

fn encrypt_data(data: &[u8], password: &str) -> AppResult<Vec<u8>> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = core_encrypt(&key, &nonce_bytes, data)?;
    let mut result = Vec::with_capacity(nonce_bytes.len() + salt.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(data: &[u8], password: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_SIZE + SALT_SIZE {
        return Err(AppError::InvalidData("File size is too small".to_string()));
    }
    let (nonce_bytes, rest) = data.split_at(NONCE_SIZE);
    let (salt, ciphertext) = rest.split_at(SALT_SIZE);
    let key = derive_key(password, salt)?;
    let nonce_array: [u8; NONCE_SIZE] = nonce_bytes.try_into().unwrap();
    core_decrypt(&key, &nonce_array, ciphertext)
}

fn encrypt_store(path: &Path, password: &str, data: &StoredData) -> AppResult<()> {
    let key = derive_key(password, &data.salt)?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut plaintext = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *plaintext, data)?;
    let ciphertext = core_encrypt(&key, &nonce_bytes, &*plaintext)?;
    plaintext.zeroize();
    let mut file_data = Vec::with_capacity(nonce_bytes.len() + data.salt.len() + ciphertext.len());
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&data.salt);
    file_data.extend_from_slice(&ciphertext);
    let tmp_path = path.with_extension("tmp");
    struct TmpFileGuard<'a> {
        path: &'a Path,
        should_delete: bool,
    }

    impl<'a> Drop for TmpFileGuard<'a> {
        fn drop(&mut self) {
            if self.should_delete && self.path.exists() {
                let _ = fs::remove_file(self.path);
            }
        }
    }

    let mut guard = TmpFileGuard {
        path: &tmp_path,
        should_delete: true,
    };

    {
        let mut tmp = File::create(&tmp_path)?;
        tmp.write_all(&file_data)?;
        tmp.flush()?;
    }
    fs::rename(&tmp_path, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    guard.should_delete = false;
    println!("Store saved to {}", path.display());
    Ok(())
}

fn decrypt_store(path: &Path, password: &str) -> AppResult<StoredData> {
    let mut f = File::open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    if data.len() < NONCE_SIZE + SALT_SIZE {
        return Err(AppError::InvalidData("File size is too small".to_string()));
    }
    let (nonce_bytes, rest) = data.split_at(NONCE_SIZE);
    let (salt, ciphertext) = rest.split_at(SALT_SIZE);
    let key = derive_key(password, salt)?;
    let nonce_array: [u8; NONCE_SIZE] = nonce_bytes.try_into().unwrap();
    let plaintext_zeroizing = core_decrypt(&key, &nonce_array, ciphertext)?;
    let parsed: StoredData = serde_json::from_slice(&*plaintext_zeroizing)?;

    Ok(parsed)
}

fn validate_base32(secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("Secret cannot be empty".to_string());
    }

    let cleaned = secret.replace(' ', "").to_uppercase();
    for ch in cleaned.chars() {
        if !matches!(ch, 'A'..='Z' | '2'..='7' | '=') {
            return Err("Invalid character in base32 secret. Only A-Z, 2-7, and = are allowed."
                .to_string());
        }
    }

    match decode(Alphabet::Rfc4648 { padding: false }, &cleaned) {
        Some(_) => Ok(()),
        None => Err("Invalid base32 format. Please check your secret.".to_string()),
    }
}

fn get_remaining_seconds(step: u64) -> u64 {
    step - ((Utc::now().timestamp() % step as i64) as u64)
}

fn calculate_otp(
    secret_b32: &Zeroizing<String>,
    counter: u64,
    algorithm: OtpAlgorithm,
    digits: u8,
) -> Option<Zeroizing<String>> {
    let cleaned = Zeroizing::new(secret_b32.replace(' ', "").to_uppercase());
    let secret_bytes = match decode(Alphabet::Rfc4648 { padding: false }, &cleaned) {
        Some(bytes) => bytes,
        None => return None,
    };
    let secret = Zeroizing::new(secret_bytes);
    let counter_bytes = counter.to_be_bytes();

    let result = Zeroizing::new(match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac = <HmacSha1 as HmacKeyInit>::new_from_slice(&*secret).ok()?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&*secret).ok()?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = <HmacSha512 as HmacKeyInit>::new_from_slice(&*secret).ok()?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    });

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);

    let divisor = match digits {
        6 => 1_000_000,
        8 => 100_000_000,
        _ => return None,
    };

    Some(Zeroizing::new(format!(
        "{:0width$}",
        code % divisor,
        width = digits as usize
    )))
}

fn generate_otp(entry: &OtpEntry) -> Option<(Zeroizing<String>, u64)> {
    match entry.otp_type {
        OtpType::Totp => {
            let timestep = (Utc::now().timestamp() / entry.step as i64) as u64;
            let code = calculate_otp(&entry.secret, timestep, entry.algorithm, entry.digits)?;
            let remaining = get_remaining_seconds(entry.step);
            Some((code, remaining))
        }
        OtpType::Hotp => {
            let code = calculate_otp(&entry.secret, entry.counter, entry.algorithm, entry.digits)?;
            Some((code, 0))
        }
    }
}

fn copy_to_clipboard(text: &str) -> AppResult<()> {
    let mut clipboard = Clipboard::new()?;

    #[cfg(target_os = "linux")]
    {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_millis(100);
        clipboard.set().wait_until(deadline).text(text)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        clipboard.set_text(text)?;
    }

    Ok(())
}

fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut prev_row: Vec<usize> = (0..=len2).collect();
    let mut curr_row = vec![0; len2 + 1];

    for (i, c1) in s1.chars().enumerate() {
        curr_row[0] = i + 1;

        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            curr_row[j + 1] = prev_row[j + 1].min(curr_row[j] + 1).min(prev_row[j] + cost);
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[len2]
}

fn suggest_similar_accounts(input: &str, entries: &HashMap<String, OtpEntry>) {
    if entries.is_empty() {
        return;
    }

    let input_lower = input.to_lowercase();
    let max_distance = 3;

    let mut suggestions: Vec<(String, usize)> = entries
        .keys()
        .filter_map(|name| {
            let name_lower = name.to_lowercase();
            let distance = levenshtein_distance(&input_lower, &name_lower);

            if distance <= max_distance
                || name_lower.contains(&input_lower)
                || input_lower.contains(&name_lower)
            {
                Some((name.clone(), distance))
            } else {
                None
            }
        })
        .collect();

    if suggestions.is_empty() {
        return;
    }

    suggestions.sort_by_key(|(_, dist)| *dist);
    suggestions.truncate(5);

    println!("\nDid you mean:");
    for (name, _) in suggestions {
        println!("  - {}", name);
    }
}

fn get_backup_path_interactive(is_encrypted: bool) -> AppResult<PathBuf> {
    print!(
        "Enter the full path of the folder where the backup will be saved. Example:(/home/user/Desktop): "
    );
    io::stdout().flush()?;
    let mut dir_input = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *dir_input)?;
    let dir_input = dir_input.trim();
    let dir_path = Path::new(dir_input);
    if !dir_path.exists() || !dir_path.is_dir() {
        println!("The specified folder does not exist.");
        return Err(AppError::InvalidData(
            "The folder could not be found".to_string(),
        ));
    }

    print!("Enter the file name (without extension): ");
    io::stdout().flush()?;
    let mut name_input = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *name_input)?;
    let name_input = name_input.trim();
    if name_input.is_empty() {
        println!("Invalid file name.");
        return Err(AppError::InvalidData("Invalid file name".to_string()));
    }

    let mut full_path = dir_path.join(name_input);
    if is_encrypted {
        full_path.set_extension("enc");
    } else {
        full_path.set_extension("txt");
    }

    if full_path.exists() {
        print!("{} already exists. Overwrite? (Y/N): ", full_path.display());
        io::stdout().flush()?;
        let mut answer = Zeroizing::new(String::new());
        io::stdin().read_line(&mut *answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Operation cancelled.");
            return Err(AppError::Cancelled("User cancellation".to_string()));
        }
    }

    Ok(full_path)
}

fn otp_entry_to_string(name: &str, entry: &OtpEntry) -> Zeroizing<String> {
    let mut s = Zeroizing::new(format!(
        "Account: {}\nSecret: {}\nType: {:?}\nAlgorithm: {:?}\nDigits: {}\n",
        name,
        entry.secret.as_str(),
        entry.otp_type,
        entry.algorithm,
        entry.digits
    ));
    match entry.otp_type {
        OtpType::Totp => s.push_str(&format!("Step: {}\n", entry.step)),
        OtpType::Hotp => s.push_str(&format!("Counter: {}\n", entry.counter)),
    }
    s.push_str(&format!("Note: {}\n", entry.note.as_str()));
    s.push('\n');
    s
}

fn otp_entry_to_uri(name: &str, entry: &OtpEntry) -> Zeroizing<String> {
    let type_str = match entry.otp_type {
        OtpType::Totp => "totp",
        OtpType::Hotp => "hotp",
    };
    let label = encode(name);
    let mut uri = Zeroizing::new(format!(
        "otpauth://{}/{}?secret={}&digits={}",
        type_str,
        label,
        entry.secret.as_str().replace(' ', ""),
        entry.digits
    ));

    let algo_str = match entry.algorithm {
        OtpAlgorithm::Sha1 => "SHA1",
        OtpAlgorithm::Sha256 => "SHA256",
        OtpAlgorithm::Sha512 => "SHA512",
    };
    uri.push_str(&format!("&algorithm={}", algo_str));

    match entry.otp_type {
        OtpType::Totp => {
            uri.push_str(&format!("&period={}", entry.step));
        }
        OtpType::Hotp => {
            uri.push_str(&format!("&counter={}", entry.counter));
        }
    }

    uri
}
fn backup_codes(store: &StoredData) -> AppResult<()> {
    if store.entries.is_empty() {
        println!("No accounts registered yet.");
        return Ok(());
    }

    println!("\nSelect Backup Format:");
    println!("1) Plain text backup (.txt)");
    println!("2) Encrypted plain text backup (.enc)");
    println!("3) otpauth:// URI list for QR code generation (.txt)");
    print!("Your choice: ");
    io::stdout().flush()?;

    let mut choice = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *choice)?;
    let choice = choice.trim();
    let (is_enc, is_uri) = match choice {
        "1" => (false, false),
        "2" => (true, false),
        "3" => (false, true),
        _ => {
            println!("Invalid choice. Operation cancelled.");
            return Ok(());
        }
    };

    let backup_path = match get_backup_path_interactive(is_enc) {
        Ok(p) => p,
        Err(AppError::Cancelled(_)) => return Ok(()),
        Err(e) => return Err(e),
    };

    let mut plaintext = Zeroizing::new(String::new());
    if is_uri {
        for (name, entry) in &store.entries {
            plaintext.push_str(&otp_entry_to_uri(name, entry));
            plaintext.push('\n');
            plaintext.push_str(&format!("Note: {}\n\n", entry.note.as_str()));
        }
    } else {
        for (name, entry) in &store.entries {
            plaintext.push_str(&otp_entry_to_string(name, entry));
        }
    }

    if is_enc {
        print!("Enter the backup password: ");
        io::stdout().flush()?;
        let pass1 = Zeroizing::new(read_password()?);
        print!("Re-enter password: ");
        io::stdout().flush()?;
        let pass2 = Zeroizing::new(read_password()?);
        let trimmed_pass1 = Zeroizing::new(pass1.trim().to_string());
        let trimmed_pass2 = Zeroizing::new(pass2.trim().to_string());
        if trimmed_pass1 != trimmed_pass2 {
            println!("Passwords do not match, operation canceled.");
            return Ok(());
        }

        match encrypt_data(plaintext.as_bytes(), &trimmed_pass1) {
            Ok(encrypted) => {
                let mut f = File::create(&backup_path)?;
                f.write_all(&encrypted)?;
                fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
                println!("Encrypted backup completed: {}", backup_path.display());
            }
            Err(e) => {
                println!("Backup encryption failed: {}", e);
                return Err(e);
            }
        }
    } else {
        println!("\n!!! SECURITY WARNING !!!");
        if is_uri {
            println!("This file will contain otpauth:// URIs including your secrets in PLAIN TEXT.");
            println!("Anyone who gets this file can access your accounts. Protect it carefully.");
        } else {
            println!("Please note that this file is UNENCRYPTED. Anyone with access to the file can read it.");
        }
        print!("To continue, type 'YES' in capital letters: ");
        io::stdout().flush()?;
        let mut confirmation = Zeroizing::new(String::new());
        io::stdin().read_line(&mut *confirmation)?;

        if confirmation.trim() != "YES" {
            println!("Backup cancelled by user.");
            return Ok(());
        }

        let mut f = File::create(&backup_path)?;
        f.write_all(plaintext.as_bytes())?;
        println!("Backup saved: {}", backup_path.display());
    }

    Ok(())
}

fn import_from_text(text: &str, store: &mut StoredData) -> usize {
    let mut added = 0;

    for block in text.split("\n\n") {
        let lines: HashMap<&str, &str> = block
            .lines()
            .filter_map(|line| {
                if let Some(index) = line.find(':') {
                    let (key, value) = line.split_at(index);
                    Some((key.trim(), value[1..].trim()))
                } else {
                    None
                }
            })
            .collect();

        if lines.is_empty() {
            continue;
        }

        let (Some(name), Some(secret), Some(otp_type_str), Some(algo_str), Some(digits_str)) = (
            lines.get("Account"),
            lines.get("Secret"),
            lines.get("Type"),
            lines.get("Algorithm"),
            lines.get("Digits"),
        ) else {
            println!("Skipping incomplete block in backup.");
            continue;
        };

        let digits: u8 = match digits_str.parse() {
            Ok(d) if d == 6 || d == 8 => d,
            _ => {
                println!("Skipping block with invalid Digits.");
                continue;
            }
        };

        let otp_type = match otp_type_str.to_lowercase().as_str() {
            "totp" => OtpType::Totp,
            "hotp" => OtpType::Hotp,
            _ => {
                println!("Skipping block with invalid Type.");
                continue;
            }
        };

        let algorithm = match algo_str.to_lowercase().as_str() {
            "sha1" => OtpAlgorithm::Sha1,
            "sha256" => OtpAlgorithm::Sha256,
            "sha512" => OtpAlgorithm::Sha512,
            _ => {
                println!("Skipping block with invalid Algorithm.");
                continue;
            }
        };

        let mut entry = OtpEntry {
            secret: Zeroizing::new(secret.to_string()),
            otp_type,
            algorithm,
            digits,
            step: 30,
            counter: 0,
            note: Zeroizing::new(lines.get("Note").unwrap_or(&"").to_string()),
        };

        match otp_type {
            OtpType::Totp => {
                let step: u64 = match lines.get("Step").and_then(|s| s.parse().ok()) {
                    Some(s) => s,
                    None => {
                        println!("Skipping TOTP block missing Step.");
                        continue;
                    }
                };
                entry.step = step;
            }
            OtpType::Hotp => {
                let counter: u64 = match lines.get("Counter").and_then(|s| s.parse().ok()) {
                    Some(c) => c,
                    None => {
                        println!("Skipping HOTP block missing Counter.");
                        continue;
                    }
                };
                entry.counter = counter;
            }
        }

        if let Err(_) = validate_base32(secret) {
            println!("Skipping account '{}' due to invalid Base32 secret.", name);
            continue;
        }

        if !store.entries.contains_key(*name) {
            store.entries.insert(name.to_string(), entry);
            added += 1;
        } else {
            println!("'{}' already exists, so it is skipped.", name);
        }
    }
    added
}

fn restore_codes_interactive(store: &mut StoredData) -> AppResult<()> {
    print!(
        "Enter the full path of the backup file you want to restore. Example:(/home/user/Desktop/backup.txt or backup.enc): "
    );
    io::stdout().flush()?;
    let mut path_input = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *path_input)?;
    let path_input = path_input.trim();
    let backup_path = Path::new(path_input);

    if !backup_path.exists() {
        println!("The specified file does not exist.");
        return Ok(());
    }

    let mut data = Vec::new();
    File::open(backup_path)?.read_to_end(&mut data)?;

    let added = if backup_path.extension().and_then(|s| s.to_str()) == Some("enc") {
        print!("Enter your backup password: ");
        io::stdout().flush()?;
        let trimmed_pass = Zeroizing::new({
            let pass = Zeroizing::new(read_password()?);
            pass.trim().to_string()
        });
        match decrypt_data(&data, &trimmed_pass) {
            Ok(plaintext) => {
                let text = Zeroizing::new(
                    String::from_utf8(plaintext.to_vec())
                        .unwrap_or_else(|_| String::from_utf8_lossy(&*plaintext).into_owned())
                );
                if text.trim().starts_with("otpauth://") {
                    import_from_uri_list(&text, store)
                } else {
                    import_from_text(&text, store)
                }
            }
            Err(
                AppError::Crypto
                | AppError::Argon2Hash(_)
                | AppError::Argon2(_)
                | AppError::Argon2Params(_)
                | AppError::InvalidData(_),
            ) => {
                println!("The password is incorrect or the file is corrupted.");
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    } else {
        let text = Zeroizing::new(String::from_utf8_lossy(&data).into_owned());
        if text.trim().starts_with("otpauth://") {
            println!("otpauth:// URI list detected. Importing...");
            import_from_uri_list(&text, store)
        } else {
            println!("Custom plain text format detected. Importing...");
            import_from_text(&text, store)
        }
    };

    println!("{} account(s) imported successfully.", added);
    Ok(())
}

fn import_from_uri_list(text: &str, store: &mut StoredData) -> usize {
    let mut added = 0;
    let mut lines_iter = text.lines().peekable();
    while let Some(line) = lines_iter.next() {
        if line.trim().is_empty() {
            continue;
        }
        let mut note = Zeroizing::new(String::new());
        if line.starts_with("otpauth://") {
            if let Some(next_line) = lines_iter.peek() {
                if next_line.starts_with("Note: ") {
                    note = Zeroizing::new(
                        next_line
                            .strip_prefix("Note: ")
                            .unwrap_or("")
                            .to_string(),
                    );
                    let _ = lines_iter.next();
                }
            }
            match parse_otpauth_uri(line) {
                Ok((name, mut entry)) => {
                    entry.note = note;
                    if !store.entries.contains_key(&*name) {
                        store.entries.insert(name.to_string(), entry);
                        println!("- Imported '{}'", &*name);
                        added += 1;
                    } else {
                        println!("- Skipped '{}' (already exists).", &*name);
                    }
                }
                Err(_) => {
                    println!("- Warning: Could not parse a line. Skipping.");
                }
            }
        } else {
            println!("- Warning: Unexpected line. Skipping.");
        }
    }
    added
}

fn edit_account(store: &mut StoredData, path: &Path, password: &str, name: &str) -> AppResult<()> {
    if !store.entries.contains_key(name) {
        println!("Account '{}' not found.", name);
        suggest_similar_accounts(name, &store.entries);
        return Ok(());
    }

    let entry = store.entries.get(name).unwrap();
    println!(
        "\nEditing account: {} (Type: {:?}, Algo: {:?}, Digits: {})",
        name, entry.otp_type, entry.algorithm, entry.digits
    );

    println!("1) Rename account");
    println!("2) Change secret");
    println!("3) Change parameters (Type, Algorithm, Digits, Step/Counter)");
    println!("4) Change note");
    println!("5) Cancel");
    print!("Choice: ");
    io::stdout().flush()?;

    let mut choice = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *choice)?;

    match choice.trim() {
        "1" => {
            print!("Enter new name: ");
            io::stdout().flush()?;
            let mut new_name = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *new_name)?;
            let new_name = Zeroizing::new(new_name.trim().to_string());

            if new_name.is_empty() {
                println!("Invalid name.");
                return Ok(());
            }

            if store.entries.contains_key(&*new_name) && *new_name != name {
                println!("An account named '{}' already exists.", &*new_name);
                return Ok(());
            }

            if let Some(secret) = store.entries.remove(name) {
                store.entries.insert(new_name.to_string(), secret);
                encrypt_store(path, password, store)?;
                println!("Account renamed from '{}' to '{}'.", name, &*new_name);
            }
        }
        "2" => {
            print!("Enter new secret (base32): ");
            io::stdout().flush()?;
            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *secret)?;
            let secret_trimmed = Zeroizing::new(secret.trim().to_string());
            if let Err(e) = validate_base32(&secret_trimmed) {
                println!("Invalid secret: {}", e);
                return Ok(());
            }

            if let Some(entry) = store.entries.get_mut(name) {
                entry.secret = secret_trimmed;
                encrypt_store(path, password, store)?;
                println!("Secret updated for '{}'.", name);
            }
        }
        "3" => {
            let mut new_entry = store.entries.get(name).unwrap().clone();

            println!("Select OTP Type:");
            println!("1) TOTP (Time-based, default)");
            println!("2) HOTP (Counter-based)");
            print!("Choice (1/2): ");
            io::stdout().flush()?;
            let mut type_choice = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *type_choice)?;

            new_entry.otp_type = match type_choice.trim() {
                "1" | "" => OtpType::Totp,
                "2" => OtpType::Hotp,
                _ => {
                    println!("Invalid choice. Operation cancelled.");
                    return Ok(());
                }
            };

            println!("Select Algorithm:");
            println!("1) SHA-1 (default)");
            println!("2) SHA-256");
            println!("3) SHA-512");
            print!("Choice (1/2/3): ");
            io::stdout().flush()?;
            let mut algo_choice = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *algo_choice)?;

            new_entry.algorithm = match algo_choice.trim() {
                "1" | "" => OtpAlgorithm::Sha1,
                "2" => OtpAlgorithm::Sha256,
                "3" => OtpAlgorithm::Sha512,
                _ => {
                    println!("Invalid choice. Operation cancelled.");
                    return Ok(());
                }
            };

            println!("Select Digits:");
            println!("1) 6 (default)");
            println!("2) 8");
            print!("Choice (1/2): ");
            io::stdout().flush()?;
            let mut digits_choice = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *digits_choice)?;

            new_entry.digits = match digits_choice.trim() {
                "1" | "" => 6,
                "2" => 8,
                _ => {
                    println!("Invalid choice. Operation cancelled.");
                    return Ok(());
                }
            };

            match new_entry.otp_type {
                OtpType::Totp => {
                    print!("Enter Time Step in seconds (e.g., 30, default 30): ");
                    io::stdout().flush()?;
                    let mut step_input = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut *step_input)?;
                    new_entry.step = match step_input.trim() {
                        "" => 30,
                        s => match s.parse::<u64>() {
                            Ok(step) if step > 0 => step,
                            _ => {
                                println!("Invalid step value. Operation cancelled.");
                                return Ok(());
                            }
                        },
                    };
                    new_entry.counter = 0;
                }
                OtpType::Hotp => {
                    print!("Enter Initial Counter value (e.g., 0, default 0): ");
                    io::stdout().flush()?;
                    let mut counter_input = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut *counter_input)?;
                    new_entry.counter = match counter_input.trim() {
                        "" => 0,
                        s => match s.parse::<u64>() {
                            Ok(counter) => counter,
                            _ => {
                                println!("Invalid counter value. Operation cancelled.");
                                return Ok(());
                            }
                        },
                    };
                    new_entry.step = 0;
                }
            }

            *store.entries.get_mut(name).unwrap() = new_entry;
            encrypt_store(path, password, store)?;
            println!("Parameters updated for '{}'.", name);
        }
        "4" => {
            print!("Enter new note: ");
            io::stdout().flush()?;
            let mut note = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *note)?;
            let note_trimmed = Zeroizing::new(note.trim().to_string());

            if let Some(entry) = store.entries.get_mut(name) {
                entry.note = note_trimmed;
                encrypt_store(path, password, store)?;
                println!("Note updated for '{}'.", name);
            }
        }
        "5" => {
            println!("Edit cancelled.");
        }
        _ => println!("Invalid choice."),
    }

    Ok(())
}

fn add_account_interactive(store: &mut StoredData, path: &Path, password: &str) -> AppResult<()> {
    println!("\nSelect addition method:");
    println!("1) Manual input");
    println!("2) otpauth URI");
    print!("Choice (1/2): ");
    io::stdout().flush()?;
    let mut method_choice = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *method_choice)?;
    let method = method_choice.trim();

    match method {
        "1" => {
            print!("Account name: ");
            io::stdout().flush()?;
            let mut name = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *name)?;
            let name = Zeroizing::new(name.trim().to_string());
            if name.is_empty() {
                println!("Invalid name");
                return Ok(());
            }
            if store.entries.contains_key(&*name) {
                println!("An account named '{}' already exists.", &*name);
                return Ok(());
            }

            print!("Secret (base32): ");
            io::stdout().flush()?;
            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *secret)?;
            let secret_trimmed = Zeroizing::new(secret.trim().to_string());
            if let Err(e) = validate_base32(&secret_trimmed) {
                println!("Error: {}", e);
                return Ok(());
            }

            println!("\nSelect OTP Type:");
            println!("1) TOTP (Time-based, default)");
            println!("2) HOTP (Counter-based)");
            print!("Choice (1/2): ");
            io::stdout().flush()?;
            let mut type_choice = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *type_choice)?;
            let otp_type = match type_choice.trim() {
                "1" | "" => OtpType::Totp,
                "2" => OtpType::Hotp,
                _ => {
                    println!("Invalid choice. Adding account cancelled.");
                    return Ok(());
                }
            };

            println!("\nSelect Algorithm:");
            println!("1) SHA-1 (default)");
            println!("2) SHA-256");
            println!("3) SHA-512");
            print!("Choice (1/2/3): ");
            io::stdout().flush()?;
            let mut algo_choice = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *algo_choice)?;

            let algorithm = match algo_choice.trim() {
                "1" | "" => OtpAlgorithm::Sha1,
                "2" => OtpAlgorithm::Sha256,
                "3" => OtpAlgorithm::Sha512,
                _ => {
                    println!("Invalid choice. Adding account cancelled.");
                    return Ok(());
                }
            };

            println!("\nSelect Digits:");
            println!("1) 6 (default)");
            println!("2) 8");
            print!("Choice (1/2): ");
            io::stdout().flush()?;
            let mut digits_choice = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *digits_choice)?;
            let digits = match digits_choice.trim() {
                "1" | "" => 6,
                "2" => 8,
                _ => {
                    println!("Invalid choice. Adding account cancelled.");
                    return Ok(());
                }
            };

            let mut new_entry = OtpEntry {
                secret: secret_trimmed,
                otp_type,
                algorithm,
                digits,
                step: 0,
                counter: 0,
                note: Zeroizing::new(String::new()),
            };

            match otp_type {
                OtpType::Totp => {
                    print!("Enter Time Step in seconds (e.g., 30, default 30): ");
                    io::stdout().flush()?;
                    let mut step_input = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut *step_input)?;
                    new_entry.step = match step_input.trim() {
                        "" => 30,
                        s => match s.parse::<u64>() {
                            Ok(step) if step > 0 => step,
                            _ => {
                                println!("Invalid step value. Adding account cancelled.");
                                return Ok(());
                            }
                        },
                    };
                }
                OtpType::Hotp => {
                    print!("Enter Initial Counter value (e.g., 0, default 0): ");
                    io::stdout().flush()?;
                    let mut counter_input = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut *counter_input)?;
                    new_entry.counter = match counter_input.trim() {
                        "" => 0,
                        s => match s.parse::<u64>() {
                            Ok(counter) => counter,
                            _ => {
                                println!("Invalid counter value. Adding account cancelled.");
                                return Ok(());
                            }
                        },
                    };
                }
            }

            print!("Enter note (optional, leave blank for none): ");
            io::stdout().flush()?;
            let mut note = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *note)?;
            new_entry.note = Zeroizing::new(note.trim().to_string());

            store.entries.insert(name.to_string(), new_entry);
            encrypt_store(path, password, store)?;
            println!("'{}' saved successfully.", &*name);
        }
        "2" => {
            print!("Enter otpauth URI: ");
            io::stdout().flush()?;
            let mut uri_str = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *uri_str)?;
            let uri_str = Zeroizing::new(uri_str.trim().to_string());
            match parse_otpauth_uri(&uri_str) {
                Ok((parsed_name, mut entry)) => {
                    print!(
                        "Parsed account name is '{}'. Enter new name to change, or leave blank to keep: ",
                        &*parsed_name
                    );
                    io::stdout().flush()?;
                    let mut name_input = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut *name_input)?;
                    let name_input_trimmed = Zeroizing::new(name_input.trim().to_string());
                    let final_name = Zeroizing::new(if name_input_trimmed.is_empty() {
                        parsed_name.to_string()
                    } else {
                        name_input_trimmed.to_string()
                    });
                    if final_name.is_empty() {
                        println!("Invalid name");
                        return Ok(());
                    }
                    if store.entries.contains_key(&*final_name) {
                        println!("An account named '{}' already exists.", &*final_name);
                        return Ok(());
                    }
                    print!("Enter note (optional, leave blank for none): ");
                    io::stdout().flush()?;
                    let mut note = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut *note)?;
                    entry.note = Zeroizing::new(note.trim().to_string());
                    store.entries.insert(final_name.to_string(), entry);
                    encrypt_store(path, password, store)?;
                    println!("'{}' saved successfully from URI.", &*final_name);
                }
                Err(e) => {
                    println!("Error parsing URI: {}", e);
                    return Ok(());
                }
            }
        }
        _ => {
            println!("Invalid choice. Adding account cancelled.");
            return Ok(());
        }
    }
    Ok(())
}
fn settings_menu(
    store: &mut StoredData,
    path: &Path,
    current_password: &mut Zeroizing<String>,
) -> AppResult<()> {
    loop {
        println!("\n=== Settings ===");
        println!(
            "1) Auto-copy codes to clipboard: {}",
            if store.settings.auto_copy_to_clipboard {
                "ON"
            } else {
                "OFF"
            }
        );
        println!(
            "2) Hide OTP codes by default: {}",
            if store.settings.hide_otp_codes {
                "ON"
            } else {
                "OFF"
            }
        );
        println!("3) Change Master Password");
        println!("4) Back to main menu");
        print!("Choice: ");
        io::stdout().flush()?;
        let mut choice = Zeroizing::new(String::new());
        io::stdin().read_line(&mut *choice)?;
        match choice.trim() {
            "1" => {
                store.settings.auto_copy_to_clipboard = !store.settings.auto_copy_to_clipboard;
                encrypt_store(path, current_password.as_str(), store)?;
                println!(
                    "Auto-copy set to: {}",
                    if store.settings.auto_copy_to_clipboard {
                        "ON"
                    } else {
                        "OFF"
                    }
                );
            }
            "2" => {
                store.settings.hide_otp_codes = !store.settings.hide_otp_codes;
                encrypt_store(path, current_password.as_str(), store)?;
                println!(
                    "Hide OTP codes set to: {}",
                    if store.settings.hide_otp_codes {
                        "ON"
                    } else {
                        "OFF"
                    }
                );
            }
            "3" => {
                match change_master_password(current_password, store) {
                    Ok(new_pass) => {
                        *current_password = new_pass;
                        return Err(AppError::Cancelled(
                            "Password changed, path update required".to_string(),
                        ));
                    }
                    Err(AppError::Cancelled(msg)) => {
                        println!("Password change cancelled: {}", msg);
                    }
                    Err(e) => {
                        println!("Password change failed: {}", e);
                        return Err(e);
                    }
                }
            }
            "4" => break,
            _ => println!("Invalid choice."),
        }
    }
    Ok(())
}

fn main() -> AppResult<()> {
    println!(r" $$\   $$\                  $$$$$$\              $$\     $$\       ");
    println!(r" $$ | $$  |                $$  __$$\             $$ |    $$ |      ");
    println!(r" $$ |$$  /  $$$$$$\        $$ /  $$ |$$\   $$\ $$$$$$\   $$$$$$$\  ");
    println!(r" $$$$$  /  $$  __$$\       $$$$$$$$ |$$ |  $$ |\_$$  _|  $$  __$$\ ");
    println!(r" $$  $$<   $$ |  \__|      $$  __$$ |$$ |  $$ |  $$ |    $$ |  $$ |");
    println!(r" $$ |\$$\  $$ |            $$ |  $$ |$$ |  $$ |  $$ |$$\ $$ |  $$ |");
    println!(r" $$ | \$$\ $$ |            $$ |  $$ |\$$$$$$  |  \$$$$  |$$ |  $$ |");
    println!(r" \__|  \__|\__|            \__|  \__| \______/    \____/ \__|  \__|");
    println!("--------------------------------------------------");
    println!(" Attention:");
    println!(" This application encrypts your data locally.");
    println!(
        " If you forget your master password, you will not be able to recover your saved accounts."
    );
    println!(" Use the backup feature to store your data securely.");
    println!("--------------------------------------------------");
    println!("Press Enter to continue...");
    io::stdout().flush()?;
    let mut dummy = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *dummy)?;
    let any_store = any_store_files_exist()?;
    let mut current_password: Zeroizing<String>;

    if any_store {
        print!("Enter your password: ");
        io::stdout().flush()?;
        current_password = Zeroizing::new(read_password()?.trim().to_string());
    } else {
        print!("Set a new password: ");
        io::stdout().flush()?;
        let first = Zeroizing::new(read_password()?);
        print!("Re-enter password: ");
        io::stdout().flush()?;
        let second = Zeroizing::new(read_password()?);
        let trimmed_first = Zeroizing::new(first.trim().to_string());
        let trimmed_second = Zeroizing::new(second.trim().to_string());
        if trimmed_first.as_str() != trimmed_second.as_str() {
            println!("Passwords do not match. Exiting.");
            return Ok(());
        }
        drop(trimmed_second);
        current_password = trimmed_first;
    }
    let mut current_path = store_path_for_password(current_password.as_str())?;
    let mut store;

    if current_path.exists() {
        match decrypt_store(&current_path, current_password.as_str()) {
            Ok(data) => {
                println!("\nStore loaded successfully: {}", current_path.display());
                store = data;
            }
            Err(AppError::Crypto | AppError::Argon2Hash(_) | AppError::InvalidData(_)) => {
                eprintln!(
                    "\nError: Could not decrypt store file '{}'. The password is incorrect or the file is corrupted.",
                    current_path.display()
                );
                eprintln!(
                    "A store file exists for this password, but could not be accessed. Exiting."
                );
                return Err(AppError::InvalidData(
                    "Password decryption or file corruption".to_string(),
                ));
            }
            Err(e) => {
                eprintln!(
                    "\nCritical error accessing store file '{}': {}",
                    current_path.display(),
                    e
                );
                return Err(e);
            }
        }
    } else {
        println!(
            "\nNo existing store found for this password. A new, encrypted file will be created at '{}' upon saving the first account.",
            current_path.display()
        );
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        store = StoredData {
            entries: HashMap::new(),
            salt: salt.to_vec(),
            settings: AppSettings::default(),
        };
    }
    loop {
        println!("\n1) Get code");
        println!("2) Add account");
        println!("3) List accounts");
        println!("4) Edit account");
        println!("5) Delete account");
        println!("6) View note");
        println!("7) Backup codes");
        println!("8) Restore codes");
        println!("9) Settings");
        println!("10) Exit");

        let mut choice = Zeroizing::new(String::new());
        io::stdin().read_line(&mut *choice)?;
        match choice.trim() {
            "1" => {
                let name = match read_account_name("Account name: ", &store.entries) {
                    Ok(name) => name,
                    Err(AppError::Io(e)) if e.to_string().contains("EOF") => {
                        println!("Input cancelled.");
                        continue;
                    }
                    Err(e) => {
                        println!("Error reading input: {}", e);
                        continue;
                    }
                };
                if let Some(entry) = store.entries.get(name.as_str()) {
                    match generate_otp(entry) {
                        Some((code, remaining)) => {
                            if store.settings.hide_otp_codes {
                                let hidden_code = "*".repeat(code.len());
                                println!("\nCode: {}", hidden_code);

                                if store.settings.auto_copy_to_clipboard {
                                    match copy_to_clipboard(&code) {
                                        Ok(_) => println!("Code copied to clipboard!"),
                                        Err(e) => println!("Could not copy to clipboard: {}", e),
                                    }
                                }

                                if entry.otp_type == OtpType::Totp {
                                    println!("Valid for {} more seconds", remaining);
                                }
                            } else {
                                println!("\nCode: {}", code.as_str());
                                if store.settings.auto_copy_to_clipboard {
                                    match copy_to_clipboard(&code) {
                                        Ok(_) => println!("Code copied to clipboard!"),
                                        Err(e) => println!("Could not copy to clipboard: {}", e),
                                    }
                                }
                                if entry.otp_type == OtpType::Totp {
                                    println!("Valid for {} more seconds", remaining);
                                }
                            }
                            if entry.otp_type == OtpType::Hotp {
                                print!("Did you SUCCESSFULLY use this HOTP code? (Y/N): ");
                                io::stdout().flush()?;
                                let mut answer = Zeroizing::new(String::new());
                                io::stdin().read_line(&mut *answer)?;

                                if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                                    if let Some(mut_entry) = store.entries.get_mut(name.as_str()) {
                                        mut_entry.counter += 1;
                                        println!(
                                            "The HOTP counter has been updated to {}.",
                                            mut_entry.counter
                                        );
                                        if let Err(e) =
                                            encrypt_store(&current_path, &current_password, &store)
                                        {
                                            println!(
                                                "Warning: Updated counter could not be saved: {}",
                                                e
                                            );
                                        }
                                    }
                                } else {
                                    println!("The counter has NOT been increased. The generated code is now invalid. You must use this code and confirm it to try again.");
                                }
                            }
                        }
                        None => {
                            println!("Failed to generate code. Check algorithm or secret.");
                        }
                    }
                } else {
                    println!("Account not found.");
                    suggest_similar_accounts(&name, &store.entries);
                }
            }
            "2" => {
                if let Err(e) = add_account_interactive(&mut store, &current_path, current_password.as_str()) {
                    eprintln!("Error adding account: {}", e);
                }
            }
            "3" => {
                if store.entries.is_empty() {
                    println!("No accounts saved yet.");
                } else {
                    println!("\nSaved Accounts (Name | Type | Algorithm | Digits):");
                    let mut sorted_keys: Vec<_> = store.entries.keys().collect();
                    sorted_keys.sort_by_key(|a| a.to_lowercase());
                    for name in sorted_keys.iter() {
                        let entry = store.entries.get(*name).unwrap();
                        println!(
                            "- {} | {:?} | {:?} | {}",
                            name, entry.otp_type, entry.algorithm, entry.digits
                        );
                    }
                }
            }

            "4" => {
                let name = match read_account_name("Account name to edit: ", &store.entries) {
                    Ok(name) => name,
                    Err(AppError::Io(e)) if e.to_string().contains("EOF") => {
                        println!("Input cancelled.");
                        continue;
                    }
                    Err(e) => {
                        println!("Error reading input: {}", e);
                        continue;
                    }
                };
                if let Err(e) = edit_account(&mut store, &current_path, current_password.as_str(), &name) {
                    eprintln!("Error saving store: {}", e);
                }
            }
            "5" => {
                let name = match read_account_name("Account to delete: ", &store.entries) {
                    Ok(name) => name,
                    Err(AppError::Io(e)) if e.to_string().contains("EOF") => {
                        println!("Input cancelled.");
                        continue;
                    }
                    Err(e) => {
                        println!("Error reading input: {}", e);
                        continue;
                    }
                };
                if store.entries.remove(name.as_str()).is_some() {
                    if let Err(e) = encrypt_store(&current_path, &current_password, &store) {
                        println!("Warning: Could not save store after deletion: {}", e);
                    } else {
                        println!("Account '{}' deleted.", name.as_str());
                    }
                } else {
                    println!("Account '{}' not found.", name.as_str());
                    suggest_similar_accounts(&name, &store.entries);
                }
            }
            "6" => {
                let name = match read_account_name("Account name to view note: ", &store.entries) {
                    Ok(name) => name,
                    Err(AppError::Io(e)) if e.to_string().contains("EOF") => {
                        println!("Input cancelled.");
                        continue;
                    }
                    Err(e) => {
                        println!("Error reading input: {}", e);
                        continue;
                    }
                };
                if let Some(entry) = store.entries.get(name.as_str()) {
                    if entry.note.is_empty() {
                        println!("No note for '{}'.", name.as_str());
                    } else {
                        println!("Note for '{}': {}", name.as_str(), entry.note.as_str());
                    }
                } else {
                    println!("Account '{}' not found.", name.as_str());
                    suggest_similar_accounts(&name, &store.entries);
                }
            }
            "7" => {
                if let Err(e) = backup_codes(&store) {
                    println!("Backup error: {}", e);
                }
            }
            "8" => {
                if let Err(e) = restore_codes_interactive(&mut store) {
                    println!("Restore error: {}", e);
                } else if store.entries.len() > 0 {
                    if let Err(e) = encrypt_store(&current_path, &current_password, &store) {
                        println!(
                            "Warning: Could not save store after successful restore: {}",
                            e
                        );
                    }
                }
            }
            "9" => {
                match settings_menu(&mut store, &current_path, &mut current_password) {
                    Ok(_) => {
                        current_path = store_path_for_password(current_password.as_str())?;
                    }
                    Err(AppError::Cancelled(msg)) => {
                        if msg.contains("Password changed") {
                            current_path = store_path_for_password(current_password.as_str())?;
                            println!("New store path is: {}", current_path.display());
                        } else {
                            println!("Operation cancelled: {}", msg);
                        }
                    }
                    Err(e) => {
                        println!("Settings error: {}", e);
                        return Err(e);
                    }
                }
            }
            "10" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid choice."),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_validate_base32_valid() {
        assert!(validate_base32("JBSWY3DPEHPK3PXP").is_ok());
        assert!(validate_base32("GEZDGNBVGY3TQOJQ").is_ok());
    }

    #[test]
    fn test_validate_base32_invalid() {
        assert!(validate_base32("INVALID!@#$").is_err());
        assert!(validate_base32("").is_err());
        assert!(validate_base32("123456789").is_err());
    }

    #[test]
    fn test_validate_base32_with_spaces() {
        assert!(validate_base32("JBSW Y3DP EHPK 3PXP").is_ok());
    }

    #[test]
    fn test_calculate_totp_sha1() {
        let secret = Zeroizing::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string());
        let result = calculate_otp(&secret, 1, OtpAlgorithm::Sha1, 6);
        assert!(result.is_some());
        let code = result.unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_numeric()));
    }

    #[test]
    fn test_calculate_totp_8_digits() {
        let secret = Zeroizing::new("JBSWY3DPEHPK3PXP".to_string());
        let result = calculate_otp(&secret, 1, OtpAlgorithm::Sha1, 8);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 8);
    }

    #[test]
    fn test_encrypt_decrypt_data() {
        let original_data = b"Hello, this is a secret message!";
        let password = "super_secret_password";
        let encrypted = encrypt_data(original_data, password).unwrap();
        assert_ne!(encrypted.as_slice(), original_data);
        let decrypted = decrypt_data(&encrypted, password).unwrap();
        assert_eq!(&*decrypted, original_data);
    }

    #[test]
    fn test_decrypt_with_wrong_password() {
        let original_data = b"Secret data";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let encrypted = encrypt_data(original_data, password).unwrap();
        let result = decrypt_data(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_otp_entry_serialization() {
        let entry = OtpEntry {
            secret: Zeroizing::new("JBSWY3DPEHPK3PXP".to_string()),
            otp_type: OtpType::Totp,
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            step: 30,
            counter: 0,
            note: Zeroizing::new(String::new()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: OtpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.otp_type, OtpType::Totp);
        assert_eq!(deserialized.algorithm, OtpAlgorithm::Sha1);
        assert_eq!(deserialized.digits, 6);
        assert_eq!(deserialized.step, 30);
    }

    #[test]
    fn test_import_from_text() {
        let backup_text = r#"Account: TestAccount
Secret: JBSWY3DPEHPK3PXP
Type: Totp
Algorithm: Sha1
Digits: 6
Step: 30

Account: TestAccount2
Secret: GEZDGNBVGY3TQOJQ
Type: Hotp
Algorithm: Sha256
Digits: 8
Counter: 5
"#;

        let mut store = StoredData {
            entries: HashMap::new(),
            salt: vec![0u8; SALT_SIZE],
            settings: AppSettings::default(),
        };
        let added = import_from_text(backup_text, &mut store);
        assert_eq!(added, 2);
        assert!(store.entries.contains_key("TestAccount"));
        assert!(store.entries.contains_key("TestAccount2"));
        let entry1 = store.entries.get("TestAccount").unwrap();
        assert_eq!(entry1.otp_type, OtpType::Totp);
        assert_eq!(entry1.digits, 6);
        let entry2 = store.entries.get("TestAccount2").unwrap();
        assert_eq!(entry2.otp_type, OtpType::Hotp);
        assert_eq!(entry2.counter, 5);
    }

    #[test]
    fn test_calculate_otp_invalid_secret() {
        let invalid_secret = Zeroizing::new("INVALID!!!".to_string());
        let result = calculate_otp(&invalid_secret, 1, OtpAlgorithm::Sha1, 6);
        assert!(result.is_none());
    }

    #[test]
    fn test_remaining_seconds() {
        let step = 30u64;
        let remaining = get_remaining_seconds(step);
        assert!(remaining > 0 && remaining <= step);
    }

    #[test]
    fn test_derive_key_performance() {
        use std::time::Instant;
        let password = "test_password";
        let salt = [0u8; SALT_SIZE];
        let start = Instant::now();
        let _key = derive_key(password, &salt).unwrap();
        let duration = start.elapsed();
        assert!(duration.as_secs() < 60);
    }

    #[test]
    fn test_encrypt_store_success() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store.enc");
        let password = "test_password";
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let mut entries = HashMap::new();
        entries.insert(
            "TestAccount".to_string(),
            OtpEntry {
                secret: Zeroizing::new("JBSWY3DPEHPK3PXP".to_string()),
                otp_type: OtpType::Totp,
                algorithm: OtpAlgorithm::Sha1,
                digits: 6,
                step: 30,
                counter: 0,
                note: Zeroizing::new(String::new()),
            },
        );

        let store = StoredData {
            entries,
            salt: salt.to_vec(),
            settings: AppSettings::default(),
        };
        encrypt_store(&store_path, password, &store).unwrap();
        assert!(store_path.exists());
        let tmp_path = store_path.with_extension("tmp");
        assert!(!tmp_path.exists(), "Tmp file should be cleaned up after success");
        let decrypted = decrypt_store(&store_path, password).unwrap();
        assert_eq!(decrypted.entries.len(), 1);
        assert!(decrypted.entries.contains_key("TestAccount"));
    }

    #[test]
    fn test_encrypt_store_tmp_cleanup_on_rename_error() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store.enc");
        let password = "test_password";
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let store = StoredData {
            entries: HashMap::new(),
            salt: salt.to_vec(),
            settings: AppSettings::default(),
        };

        File::create(&store_path).unwrap();
        let parent_perms = fs::Permissions::from_mode(0o444);
        fs::set_permissions(temp_dir.path(), parent_perms).unwrap();
        let tmp_path = store_path.with_extension("tmp");
        let result = encrypt_store(&store_path, password, &store);
        let restore_perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(temp_dir.path(), restore_perms).unwrap();
        assert!(result.is_err());
        assert!(!tmp_path.exists(), "Tmp file should be cleaned up after rename error");
    }

    #[test]
    fn test_encrypt_store_no_leftover_tmp_files() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store.enc");
        let password = "test_password";
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let store = StoredData {
            entries: HashMap::new(),
            salt: salt.to_vec(),
            settings: AppSettings::default(),
        };
        for _ in 0..5 {
            encrypt_store(&store_path, password, &store).unwrap();
        }
        let file_count = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .count();
        assert_eq!(
            file_count, 1,
            "Should only have the main .enc file, no .tmp leftovers"
        );
        let tmp_path = store_path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_encrypt_store_concurrent_tmp_cleanup() {
        use std::sync::Arc;
        use std::thread;
        let temp_dir = TempDir::new().unwrap();
        let store_path = Arc::new(temp_dir.path().join("test_store.enc"));
        let password = "test_password";
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let store = Arc::new(StoredData {
            entries: HashMap::new(),
            salt: salt.to_vec(),
            settings: AppSettings::default(),
        });

        let mut handles = vec![];
        for _ in 0..5 {
            let store_path = Arc::clone(&store_path);
            let store = Arc::clone(&store);
            let handle = thread::spawn(move || {
                encrypt_store(&store_path, password, &store)
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join().unwrap();
        }

        let file_count = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .count();
        assert_eq!(
            file_count, 1,
            "Should only have the main .enc file, no .tmp leftovers"
        );
        let tmp_path = store_path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }
    
    #[test]
    fn test_zeroizing_drops_correctly() {
        use zeroize::Zeroize;
        let mut secret = Zeroizing::new(String::from("sensitive_data"));
        assert_eq!(*secret, "sensitive_data", "Initial data should match");
        secret.zeroize();
        assert!(secret.is_empty(), "String should be empty after zeroizing");
        *secret = String::from("new_data");
        assert_eq!(*secret, "new_data", "String should accept new data after zeroizing");
    }
}
