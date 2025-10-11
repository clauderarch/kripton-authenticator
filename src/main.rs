use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray, rand_core::RngCore},
    Aes256Gcm, Nonce,
};
use base32::{Alphabet, decode};
use chrono::Utc;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as HmacKeyInit;
use serde::{Deserialize, Serialize};
use rpassword::read_password;
use sha2::{Digest, Sha256, Sha512};
use argon2::{Argon2, Params, Version, Algorithm as ArgonAlgorithm};
use directories::ProjectDirs;
use zeroize::Zeroizing;

type HmacSha1 = Hmac<sha1::Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

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
}

#[derive(Serialize, Deserialize, Debug)]
struct StoredData {
    entries: HashMap<String, OtpEntry>,
    salt: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct OldStoredData {
    entries: HashMap<String, String>,
    salt: Vec<u8>,
}


const ARGON2_TIME: u32 = 3;       
const ARGON2_MEMORY: u32 = 131072;
const ARGON2_PARALLELISM: u32 = 4; 

const STORE_FILE_BASE: &str = "auth_store";

fn get_project_dirs() -> io::Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("com", "YourOrg", "KriptonAuthenticator") {
        let data_dir = proj_dirs.data_dir();
        fs::create_dir_all(data_dir)?;
        Ok(data_dir.to_path_buf())
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "Could not find a valid home directory."))
    }
}

fn store_path_for_password(password: &str) -> io::Result<PathBuf> {
    let data_dir = get_project_dirs()?;

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hexdigest = format!("{:x}", result);
    let prefix = &hexdigest[..8];
    let file_name = format!("{}_{}.enc", STORE_FILE_BASE, prefix);
    
    Ok(data_dir.join(file_name))
}

fn any_store_files_exist() -> io::Result<bool> {
    let data_dir = match get_project_dirs() {
        Ok(dir) => dir,
        Err(_) => return Ok(false), 
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

fn derive_key(password: &str, salt: &[u8]) -> GenericArray<u8, typenum::U32> {
    let params = Params::new(
        ARGON2_MEMORY,
        ARGON2_TIME,
        ARGON2_PARALLELISM,
        Some(32),
    ).expect("Argon2 parameters could not be created (This should not happen)");

    let argon2 = Argon2::new(
        ArgonAlgorithm::Argon2id,
        Version::V0x13,
        params,
    );

    let mut key = Zeroizing::new([0u8; 32]);

    argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut *key
    ).expect("Argon2 key derivation failed (Critical error)");

    GenericArray::clone_from_slice(&*key)
}

fn encrypt_data(data: &[u8], password: &str) -> io::Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(data: &[u8], password: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if data.len() < 12 + 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid file"));
    }
    let (nonce_bytes, rest) = data.split_at(12);
    let (salt, ciphertext) = rest.split_at(16);

    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
    
    Ok(Zeroizing::new(plaintext))
}

fn encrypt_store(path: &Path, password: &str, data: &StoredData) -> io::Result<()> {
    let key = derive_key(password, &data.salt);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Serialization failed: {}", e)))?;
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    let mut file_data = Vec::new();
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&data.salt);
    file_data.extend_from_slice(&ciphertext);

    let tmp_path = path.with_extension("tmp");
    {
        let mut tmp = File::create(&tmp_path)?;
        tmp.write_all(&file_data)?;
        tmp.flush()?;
    }
    fs::rename(&tmp_path, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    println!("Store saved to {}", path.display());
    Ok(())
}

fn decrypt_store(path: &Path, password: &str) -> io::Result<StoredData> {
    let mut f = File::open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    if data.len() < 12 + 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
    }

    let (nonce_bytes, rest) = data.split_at(12);
    let (salt, ciphertext) = rest.split_at(16);

    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
    
    let plaintext_zeroizing = Zeroizing::new(plaintext);
    
    match serde_json::from_slice::<StoredData>(&*plaintext_zeroizing) {
        Ok(parsed) => {
            println!("INFO: Store successfully loaded using NEW structure.");
            Ok(parsed)
        }
        Err(new_struct_err) => {
            eprintln!("WARNING: Failed to parse with new structure. Trying old structure...");

            match serde_json::from_slice::<OldStoredData>(&*plaintext_zeroizing) {
                Ok(old_data) => {
                    println!("INFO: Store successfully loaded using OLD structure. Migrating data to new format...");
                    
                    let mut new_entries = HashMap::new();
                    for (name, secret_b32_string) in old_data.entries {
                        let entry = OtpEntry {
                            secret: Zeroizing::new(secret_b32_string),
                            otp_type: OtpType::Totp,
                            algorithm: OtpAlgorithm::Sha1,
                            digits: 6,
                            step: 30,
                            counter: 0,
                        };
                        new_entries.insert(name, entry);
                    }

                    Ok(StoredData {
                        entries: new_entries,
                        salt: old_data.salt,
                    })
                }
                Err(old_struct_err) => {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "json decode failed (File structure mismatch or corruption)"))
                }
            }
        }
    }
}

fn validate_base32(secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("Secret cannot be empty".to_string());
    }
    
    let cleaned = secret.replace(" ", "").to_uppercase();
    
    for ch in cleaned.chars() {
        if !matches!(ch, 'A'..='Z' | '2'..='7' | '=') {
            return Err(format!("Invalid character '{}' in base32 secret. Only A-Z, 2-7, and = are allowed.", ch));
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

fn calculate_otp(secret_b32: &Zeroizing<String>, counter: u64, algorithm: OtpAlgorithm, digits: u8) -> Option<String> {
    let cleaned = secret_b32.replace(" ", "").to_uppercase();
    let secret_bytes = decode(Alphabet::Rfc4648 { padding: false }, &cleaned)?;
    let secret = Zeroizing::new(secret_bytes);
    let counter_bytes = counter.to_be_bytes();
    let result = match algorithm {
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
    };

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

    Some(format!("{:0width$}", code % divisor, width = digits as usize))
}

fn generate_otp(entry: &OtpEntry) -> Option<(String, u64)> {
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


fn get_backup_path_interactive(is_encrypted: bool) -> io::Result<PathBuf> {
    print!("Enter the full path of the folder where the backup will be saved. Example:(/home/user/Desktop): ");
    io::stdout().flush()?;
    let mut dir_input = String::new();
    io::stdin().read_line(&mut dir_input)?;
    let dir_input = dir_input.trim();
    let dir_path = Path::new(dir_input);

    if !dir_path.exists() || !dir_path.is_dir() {
        println!("The specified folder does not exist.");
        return Err(io::Error::new(io::ErrorKind::NotFound, "Folder not found"));
    }

    print!("Enter the file name (without extension): ");
    io::stdout().flush()?;
    let mut name_input = String::new();
    io::stdin().read_line(&mut name_input)?;
    let name_input = name_input.trim();
    if name_input.is_empty() {
        println!("Invalid file name.");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid name"));
    }

    let mut full_path = dir_path.join(name_input);
    if is_encrypted {
        full_path.set_extension("enc");
    } else {
        full_path.set_extension("txt");
    }

    if full_path.exists() {
        print!("{} already exists, should we write on it? (Y/N): ", full_path.display());
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("The transaction has been canceled.");
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "user cancelled"));
        }
    }

    Ok(full_path)
}

fn otp_entry_to_string(name: &str, entry: &OtpEntry) -> String {
    let mut s = format!("Account: {}\nSecret: {}\nType: {:?}\nAlgorithm: {:?}\nDigits: {}\n", 
                        name, entry.secret.as_str(), entry.otp_type, entry.algorithm, entry.digits);
    match entry.otp_type {
        OtpType::Totp => s.push_str(&format!("Step: {}\n", entry.step)),
        OtpType::Hotp => s.push_str(&format!("Counter: {}\n", entry.counter)),
    }
    s.push('\n');
    s
}


fn backup_codes(store: &StoredData) -> io::Result<()> {
    if store.entries.is_empty() {
        println!("No accounts have been registered yet.");
        return Ok(());
    }

    println!("1) Plain text backup (.txt)");
    println!("2) Encrypted backup (.enc)");
    print!("Your choice: ");
    io::stdout().flush()?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let is_enc = choice == "2";
    let backup_path = match get_backup_path_interactive(is_enc) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };

    let mut plaintext = Zeroizing::new(String::new());
    for (name, entry) in &store.entries {
        plaintext.push_str(&otp_entry_to_string(name, entry));
    }

    if is_enc {
        print!("Enter the back up password: ");
        io::stdout().flush()?;
        let pass1 = Zeroizing::new(read_password().expect("Password could not be read"));
        print!("Entry password again: ");
        io::stdout().flush()?;
        let pass2 = Zeroizing::new(read_password().expect("Password could not be read"));

        let trimmed_pass1 = pass1.trim();
        let trimmed_pass2 = pass2.trim();

        if trimmed_pass1 != trimmed_pass2 {
            println!("Passwords do not match, transaction canceled.");
            return Ok(());
        }

        match encrypt_data(plaintext.as_bytes(), trimmed_pass1) {
            Ok(encrypted) => {
                let mut f = File::create(&backup_path)?;
                f.write_all(&encrypted)?;
                fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
                println!("Encrypted back up completed: {}", backup_path.display());
            },
            Err(e) => {
                println!("Backup encryption failed: {}", e);
            }
        }
    } else {
        println!("\n!!! SECURITY WARNING !!!");
        println!("Please note that this file is unencrypted. Anyone with access to the file can read it. Please be aware of this risk.");
        print!("To continue, type ‘YES’ in capital letters: ");
        io::stdout().flush()?;
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        
        if confirmation.trim() != "YES" {
            println!("Plain text backup cancelled by user.");
            return Ok(());
        }
        
        let mut f = File::create(&backup_path)?;
        f.write_all(plaintext.as_bytes())?;
        println!("Plain text backup completed: {}", backup_path.display());
    }

    Ok(())
}

fn import_from_text(text: &str, store: &mut StoredData) -> usize {
    let mut added = 0;
    
    for block in text.split("\n\n") {
        let lines: HashMap<&str, &str> = block.lines()
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

        let (Some(name), Some(secret), Some(otp_type_str), Some(algo_str), Some(digits_str)) = 
            (lines.get("Account"), lines.get("Secret"), lines.get("Type"), lines.get("Algorithm"), lines.get("Digits")) 
        else {
            println!("Skipping incomplete block in backup.");
            continue;
        };
        
        let digits: u8 = match digits_str.parse() {
            Ok(d) if d == 6 || d == 8 => d,
            _ => { println!("Skipping block with invalid Digits: {}", digits_str); continue; }
        };
        
        let otp_type = match otp_type_str.to_lowercase().as_str() {
            "totp" => OtpType::Totp,
            "hotp" => OtpType::Hotp,
            _ => { println!("Skipping block with invalid Type: {}", otp_type_str); continue; }
        };
        
        let algorithm = match algo_str.to_lowercase().as_str() {
            "sha1" => OtpAlgorithm::Sha1,
            "sha256" => OtpAlgorithm::Sha256,
            "sha512" => OtpAlgorithm::Sha512,
            _ => { println!("Skipping block with invalid Algorithm: {}", algo_str); continue; }
        };
        
        let mut entry = OtpEntry {
            secret: Zeroizing::new(secret.to_string()),
            otp_type,
            algorithm,
            digits,
            step: 30, 
            counter: 0,
        };

        match otp_type {
            OtpType::Totp => {
                let step: u64 = match lines.get("Step").and_then(|s| s.parse().ok()) {
                    Some(s) => s,
                    None => { println!("Skipping TOTP block missing Step."); continue; }
                };
                entry.step = step;
            }
            OtpType::Hotp => {
                let counter: u64 = match lines.get("Counter").and_then(|s| s.parse().ok()) {
                    Some(c) => c,
                    None => { println!("Skipping HOTP block missing Counter."); continue; }
                };
                entry.counter = counter;
            }
        }
        
        if let Err(e) = validate_base32(secret) {
            println!("Skipping account '{}' due to invalid Base32 secret: {}", name, e);
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

fn restore_codes_interactive(store: &mut StoredData) -> io::Result<()> {
    print!("Enter the full path of the backup file you want to upload: ");
    io::stdout().flush()?;
    let mut path_input = String::new();
    io::stdin().read_line(&mut path_input)?;
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
        let pass = Zeroizing::new(read_password().expect("The password could not be read."));
        match decrypt_data(&data, pass.trim()) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&*plaintext);
                let count = import_from_text(&text, store);
                count
            }
            Err(_) => {
                println!("The password is incorrect or the file is corrupted.");
                return Ok(());
            }
        }
    } else {
        let text = String::from_utf8_lossy(&data);
        import_from_text(&text, store)
    };

    println!("{} new account loaded", added);
    Ok(())
}

fn edit_account(store: &mut StoredData, path: &Path, password: &str) -> io::Result<()> {
    print!("Account name to edit: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim();
    
    if !store.entries.contains_key(name) {
        println!("Account '{}' not found.", name);
        return Ok(());
    }
    
    let entry = store.entries.get(name).unwrap();
    println!("\nEditing account: {} (Type: {:?}, Algo: {:?}, Digits: {})", 
             name, entry.otp_type, entry.algorithm, entry.digits);
    
    println!("1) Rename account");
    println!("2) Update secret");
    println!("3) Update parameters (Type/Algo/Digits/Step/Counter)");
    println!("4) Cancel");
    print!("Choice: ");
    io::stdout().flush()?;
    
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    
    match choice.trim() {
        "1" => {
            print!("Enter new name: ");
            io::stdout().flush()?;
            let mut new_name = String::new();
            io::stdin().read_line(&mut new_name)?;
            let new_name = new_name.trim().to_string();
            
            if new_name.is_empty() {
                println!("Invalid name.");
                return Ok(());
            }
            
            if store.entries.contains_key(&new_name) && new_name != name {
                println!("An account named '{}' already exists.", new_name);
                return Ok(());
            }
            
            if let Some(secret) = store.entries.remove(name) {
                store.entries.insert(new_name.clone(), secret);
                encrypt_store(path, password, store)?;
                println!("Account renamed from '{}' to '{}'.", name, new_name);
            }
        }
        "2" => {
            print!("Enter new secret (base32): ");
            io::stdout().flush()?;
            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut *secret)?;
            let secret_trimmed = secret.trim().to_string();
            
            if let Err(e) = validate_base32(&secret_trimmed) {
                println!("Invalid secret: {}", e);
                return Ok(());
            }
            
            if let Some(entry) = store.entries.get_mut(name) {
                entry.secret = Zeroizing::new(secret_trimmed);
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
            let mut type_choice = String::new();
            io::stdin().read_line(&mut type_choice)?;
            
            new_entry.otp_type = match type_choice.trim() {
                "1" | "" => OtpType::Totp,
                "2" => OtpType::Hotp,
                _ => { println!("Invalid choice. Operation cancelled."); return Ok(()); }
            };
            
            println!("Select Algorithm:");
            println!("1) SHA-1 (default)");
            println!("2) SHA-256");
            println!("3) SHA-512");
            print!("Choice (1/2/3): ");
            io::stdout().flush()?;
            let mut algo_choice = String::new();
            io::stdin().read_line(&mut algo_choice)?;

            new_entry.algorithm = match algo_choice.trim() {
                "1" | "" => OtpAlgorithm::Sha1,
                "2" => OtpAlgorithm::Sha256,
                "3" => OtpAlgorithm::Sha512,
                _ => { println!("Invalid choice. Operation cancelled."); return Ok(()); }
            };

            println!("Select Digits:");
            println!("1) 6 (default)");
            println!("2) 8");
            print!("Choice (1/2): ");
            io::stdout().flush()?;
            let mut digits_choice = String::new();
            io::stdin().read_line(&mut digits_choice)?;

            new_entry.digits = match digits_choice.trim() {
                "1" | "" => 6,
                "2" => 8,
                _ => { println!("Invalid choice. Operation cancelled."); return Ok(()); }
            };

            match new_entry.otp_type {
                OtpType::Totp => {
                    print!("Enter Time Step in seconds (e.g., 30, default 30): ");
                    io::stdout().flush()?;
                    let mut step_input = String::new();
                    io::stdin().read_line(&mut step_input)?;
                    new_entry.step = match step_input.trim() {
                        "" => 30,
                        s => match s.parse::<u64>() {
                            Ok(step) if step > 0 => step,
                            _ => { println!("Invalid step value. Operation cancelled."); return Ok(()); }
                        }
                    };
                    new_entry.counter = 0;
                }
                OtpType::Hotp => {
                    print!("Enter Initial Counter value (e.g., 0, default 0): ");
                    io::stdout().flush()?;
                    let mut counter_input = String::new();
                    io::stdin().read_line(&mut counter_input)?;
                    new_entry.counter = match counter_input.trim() {
                        "" => 0,
                        s => match s.parse::<u64>() {
                            Ok(counter) => counter,
                            _ => { println!("Invalid counter value. Operation cancelled."); return Ok(()); }
                        }
                    };
                    new_entry.step = 0;
                }
            }

            *store.entries.get_mut(name).unwrap() = new_entry;
            encrypt_store(path, password, store)?;
            println!("Parameters updated for '{}'.", name);

        }
        "4" => {
            println!("Edit cancelled.");
        }
        _ => println!("Invalid choice."),
    }
    
    Ok(())
}


fn add_account_interactive(store: &mut StoredData, path: &Path, password: &str) -> io::Result<()> {
    print!("Account name: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim().to_string();
    if name.is_empty() {
        println!("Invalid name");
        return Ok(());
    }
    if store.entries.contains_key(&name) {
        println!("An account named '{}' already exists.", name);
        return Ok(());
    }

    print!("Secret (base32): ");
    io::stdout().flush()?;
    let mut secret = Zeroizing::new(String::new());
    io::stdin().read_line(&mut *secret)?;
    let secret_trimmed = secret.trim().to_string();
    
    if let Err(e) = validate_base32(&secret_trimmed) {
        println!("Error: {}", e);
        return Ok(());
    }

    println!("\nSelect OTP Type:");
    println!("1) TOTP (Time-based, default)");
    println!("2) HOTP (Counter-based)");
    print!("Choice (1/2): ");
    io::stdout().flush()?;
    let mut type_choice = String::new();
    io::stdin().read_line(&mut type_choice)?;
    
    let otp_type = match type_choice.trim() {
        "1" | "" => OtpType::Totp,
        "2" => OtpType::Hotp,
        _ => { println!("Invalid choice. Adding account cancelled."); return Ok(()); }
    };
    
    println!("\nSelect Algorithm:");
    println!("1) SHA-1 (default)");
    println!("2) SHA-256");
    println!("3) SHA-512");
    print!("Choice (1/2/3): ");
    io::stdout().flush()?;
    let mut algo_choice = String::new();
    io::stdin().read_line(&mut algo_choice)?;

    let algorithm = match algo_choice.trim() {
        "1" | "" => OtpAlgorithm::Sha1,
        "2" => OtpAlgorithm::Sha256,
        "3" => OtpAlgorithm::Sha512,
        _ => { println!("Invalid choice. Adding account cancelled."); return Ok(()); }
    };

    println!("\nSelect Digits:");
    println!("1) 6 (default)");
    println!("2) 8");
    print!("Choice (1/2): ");
    io::stdout().flush()?;
    let mut digits_choice = String::new();
    io::stdin().read_line(&mut digits_choice)?;

    let digits = match digits_choice.trim() {
        "1" | "" => 6,
        "2" => 8,
        _ => { println!("Invalid choice. Adding account cancelled."); return Ok(()); }
    };

    let mut new_entry = OtpEntry {
        secret: Zeroizing::new(secret_trimmed),
        otp_type,
        algorithm,
        digits,
        step: 0,
        counter: 0,
    };

    match otp_type {
        OtpType::Totp => {
            print!("Enter Time Step in seconds (e.g., 30, default 30): ");
            io::stdout().flush()?;
            let mut step_input = String::new();
            io::stdin().read_line(&mut step_input)?;
            new_entry.step = match step_input.trim() {
                "" => 30,
                s => match s.parse::<u64>() {
                    Ok(step) if step > 0 => step,
                    _ => { println!("Invalid step value. Adding account cancelled."); return Ok(()); }
                }
            };
        }
        OtpType::Hotp => {
            print!("Enter Initial Counter value (e.g., 0, default 0): ");
            io::stdout().flush()?;
            let mut counter_input = String::new();
            io::stdin().read_line(&mut counter_input)?;
            new_entry.counter = match counter_input.trim() {
                "" => 0,
                s => match s.parse::<u64>() {
                    Ok(counter) => counter,
                    _ => { println!("Invalid counter value. Adding account cancelled."); return Ok(()); }
                }
            };
        }
    }
    
    store.entries.insert(name.clone(), new_entry);
    encrypt_store(path, password, store)?;
    println!("'{}' saved.", name);
    Ok(())
}


fn main() -> io::Result<()> {
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
    println!(" If you forget your master password, you will not be able to recover your saved accounts.");
    println!(" Use the backup feature to store your data securely.");
    println!("--------------------------------------------------");
    println!("Press Enter to continue...");
    io::stdout().flush()?;
    let mut dummy = String::new();
    io::stdin().read_line(&mut dummy)?;

    let any_store = any_store_files_exist()?;
    let password: Zeroizing<String>;

    if any_store {
        print!("Enter your password: ");
        io::stdout().flush()?;
        password = Zeroizing::new(read_password().expect("The password could not be read."));
    } else {
        print!("Set a new password: ");
        io::stdout().flush()?;
        let first = Zeroizing::new(read_password().expect("The password could not be read."));
        print!("Re-enter password: ");
        io::stdout().flush()?;
        let second = Zeroizing::new(read_password().expect("The password could not be read."));
        if first.trim() != second.trim() {
            println!("Passwords do not match. Exiting.");
            return Ok(());
        }
        password = Zeroizing::new(first.trim().to_string());
    }
    
    let path = store_path_for_password(&password)?;
    let mut store;

    if path.exists() {
        match decrypt_store(&path, &password) {
            Ok(data) => {
                println!("\nStore loaded successfully: {}", path.display());
                store = data;
            },
            Err(e) => {
                eprintln!("\nError: Could not decrypt store file '{}'. The password is incorrect or the file is corrupted. Detail: {}", path.display(), e);
                eprintln!("A store file exists for this password, but could not be accessed. Exiting.");
                return Err(e);
            }
        }
    } else {
        println!("\nNo existing store found for this password. A new, encrypted file will be created at '{}' upon saving the first account.", path.display());
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        store = StoredData { entries: HashMap::new(), salt: salt.to_vec() };
    };

    loop {
        println!("\n1) Add account");
        println!("2) Get code");
        println!("3) Edit account");
        println!("4) Delete account");
        println!("5) List accounts");
        println!("6) Backup codes");
        println!("7) Restore codes");
        println!("8) Exit");
        print!("Choice: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        match choice.trim() {
            "1" => {
                if let Err(e) = add_account_interactive(&mut store, &path, &password) {
                     println!("Add account error: {}", e);
                }
            }
            "2" => {
                print!("Account name: ");
                io::stdout().flush()?;
                let mut name = String::new();
                io::stdin().read_line(&mut name)?;
                let name = name.trim();
                if let Some(entry) = store.entries.get(name) {
                    match generate_otp(entry) {
                        Some((code, remaining)) => {
                            println!("\nCode: {}", code);
                            if entry.otp_type == OtpType::Totp {
                                println!("Valid for {} more seconds", remaining);
                            } else {
                                if let Some(mut_entry) = store.entries.get_mut(name) {
                                    mut_entry.counter += 1;
                                    println!("HOTP counter incremented to {}", mut_entry.counter);
                                    if let Err(e) = encrypt_store(&path, &password, &store) {
                                        println!("Warning: Could not save updated counter: {}", e);
                                    }
                                }
                            }
                        }
                        None => {
                            println!("Failed to generate code. Check algorithm or secret.");
                        }
                    }
                } else {
                    println!("Account not found.");
                }
            }
            "3" => {
                if let Err(e) = edit_account(&mut store, &path, &password) {
                    println!("Edit error: {}", e);
                }
            }
            "4" => {
                print!("Account to delete: ");
                io::stdout().flush()?;
                let mut name = String::new();
                io::stdin().read_line(&mut name)?;
                let name = name.trim();
                if store.entries.remove(name).is_some() {
                    encrypt_store(&path, &password, &store)?;
                    println!("Account '{}' deleted.", name);
                } else {
                    println!("Account '{}' not found.", name);
                }
            }
            "5" => {
                if store.entries.is_empty() {
                    println!("No accounts saved yet.");
                } else {
                    println!("\nSaved Accounts (Name | Type | Algorithm | Digits):");
                    let mut sorted_keys: Vec<_> = store.entries.keys().collect();
                    sorted_keys.sort_by_key(|a| a.to_lowercase());
                    for name in sorted_keys.iter() {
                        let entry = store.entries.get(*name).unwrap();
                        println!("- {} | {:?} | {:?} | {}", 
                                 name, entry.otp_type, entry.algorithm, entry.digits);
                    }
                }
            }
            "6" => {
                if let Err(e) = backup_codes(&store) {
                    println!("Backup error: {}", e);
                }
            }
            "7" => {
                if let Err(e) = restore_codes_interactive(&mut store) {
                    println!("Restore error: {}", e);
                } else {
                    encrypt_store(&path, &password, &store)?;
                }
            }
            "8" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid choice.."),
        }
    }

    Ok(())
}
