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
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use rpassword::read_password;
use sha2::{Digest, Sha256};
type HmacSha1 = Hmac<sha1::Sha1>;

#[derive(Serialize, Deserialize, Debug)]
struct StoredData {
    entries: HashMap<String, String>,
    salt: Vec<u8>,
}

const PBKDF2_ROUNDS: u32 = 250_000;
const STORE_FILE_BASE: &str = "auth_store";

fn derive_key(password: &str, salt: &[u8]) -> GenericArray<u8, typenum::U32> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    GenericArray::clone_from_slice(&key)
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

fn decrypt_data(data: &[u8], password: &str) -> io::Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid file"));
    }
    let (nonce_bytes, rest) = data.split_at(12);
    let (salt, ciphertext) = rest.split_at(16);

    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))
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

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
    let parsed: StoredData = serde_json::from_slice(&plaintext).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "json decode failed"))?;
    Ok(parsed)
}

fn generate_totp(secret_b32: &str) -> Option<String> {
    let secret = decode(Alphabet::RFC4648 { padding: false }, secret_b32)?;
    let timestep = (Utc::now().timestamp() / 30) as u64;
    let counter = timestep.to_be_bytes();

    let mut mac = <HmacSha1 as HmacKeyInit>::new_from_slice(&secret).ok()?;
    mac.update(&counter);
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);

    Some(format!("{:06}", code % 1_000_000))
}

fn store_path_for_password(password: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hexdigest = format!("{:x}", result);
    let prefix = &hexdigest[..8];
    PathBuf::from(format!("{}_{}.enc", STORE_FILE_BASE, prefix))
}

fn any_store_files_exist() -> io::Result<bool> {
    for entry in fs::read_dir(".")? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with(&format!("{}_", STORE_FILE_BASE)) && name.ends_with(".enc") {
                return Ok(true);
            }
        }
    }
    Ok(false)
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

    let mut plaintext = String::new();
    for (name, secret) in &store.entries {
        plaintext.push_str(&format!("Account: {}\nSecret: {}\n\n", name, secret));
    }

    if is_enc {
        print!("Enter the back up password ");
        io::stdout().flush()?;
        let pass1 = read_password().expect("Password could not be read");
        print!("Entry password again: ");
        io::stdout().flush()?;
        let pass2 = read_password().expect("Password could not be read");

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
        let mut f = File::create(&backup_path)?;
        f.write_all(plaintext.as_bytes())?;
        println!("Plain text backup completed: {}", backup_path.display());
    }

    Ok(())
}

fn import_from_text(text: &str, store: &mut StoredData) -> usize {
    let mut added = 0;
    for block in text.split("\n\n") {
        let mut lines = block.lines();
        if let (Some(name_line), Some(secret_line)) = (lines.next(), lines.next()) {
            if name_line.starts_with("Account:") && secret_line.starts_with("Secret:") {
                let name = name_line["Account:".len()..].trim();
                let secret = secret_line["Secret:".len()..].trim();
                if !store.entries.contains_key(name) {
                    store.entries.insert(name.to_string(), secret.to_string());
                    added += 1;
                } else {
                    println!("'{}' already exists, so it is skipped.", name);
                }
            }
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
        let pass = read_password().expect("The password could not be read.");
        match decrypt_data(&data, pass.trim()) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                import_from_text(&text, store)
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

fn main() -> io::Result<()> {
    println!("Kripton Authenticator");
    println!("--------------------------------------------------");
    println!(" Attention:");
    println!(" This application encrypts your data locally.");
    println!(" If you forget your master password, you will not be able to recover your saved accounts.");
    println!(" Use the backup feature to store your data safely.");
    println!("--------------------------------------------------");
    println!("Press Enter to continue...");
    io::stdout().flush()?;
    let mut dummy = String::new();
    io::stdin().read_line(&mut dummy)?;

    let any_store = any_store_files_exist()?;
    let password: String;

    if any_store {
        print!("Enter your password: ");
        io::stdout().flush()?;
        password = read_password().expect("The password could not be read.");
    } else {
        print!("Set a new password: ");
        io::stdout().flush()?;
        let first = read_password().expect("The password could not be read.");
        print!("Re-enter password: ");
        io::stdout().flush()?;
        let second = read_password().expect("The password could not be read.");
        if first.trim() != second.trim() {
            println!("Passwords do not match. Exiting.");
            return Ok(());
        }
        password = first.trim().to_string();
    }

    let path = store_path_for_password(&password);
    let mut store;

    if path.exists() {
        match decrypt_store(&path, &password) {
            Ok(data) => {
                println!("\nStore loaded successfully: {}", path.file_name().unwrap_or_default().to_string_lossy());
                store = data;
            },
            Err(e) => {
                eprintln!("\nError: Could not decrypt store file '{}'. The password is incorrect or the file is corrupted.", path.file_name().unwrap_or_default().to_string_lossy());
                eprintln!("A store file exists for this password, but could not be accessed. Exiting.");
                return Err(e);
            }
        }
    } else {
        println!("\nNo existing store found for this password. A new, encrypted file will be created upon saving the first account.");
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        store = StoredData { entries: HashMap::new(), salt: salt.to_vec() };
    };

    loop {
        println!("\n1) Add account");
        println!("2) Get code");
        println!("3) Delete account");
        println!("4) List accounts");
        println!("5) Backup codes");
        println!("6) Restore codes");
        println!("7) Exit");
        print!("Choice: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        match choice.trim() {
            "1" => {
                print!("Account name: ");
                io::stdout().flush()?;
                let mut name = String::new();
                io::stdin().read_line(&mut name)?;
                let name = name.trim().to_string();
                if name.is_empty() {
                    println!("Invaild name");
                    continue;
                }
                if store.entries.contains_key(&name) {
                    println!("An account named '{}' already exists.", name);
                    continue;
                }
                print!("Secret (base32): ");
                io::stdout().flush()?;
                let mut secret = String::new();
                io::stdin().read_line(&mut secret)?;
                let secret = secret.trim().to_string();
                store.entries.insert(name.clone(), secret);
                encrypt_store(&path, &password, &store)?;
                println!("'{}' saved.", name);
            }
            "2" => {
                print!("Account name: ");
                io::stdout().flush()?;
                let mut name = String::new();
                io::stdin().read_line(&mut name)?;
                let name = name.trim();
                if let Some(secret) = store.entries.get(name) {
                    if let Some(code) = generate_totp(secret) {
                        println!("Code: {}", code);
                    } else {
                        println!("Failed to generate code.");
                    }
                } else {
                    println!("Account not found.");
                }
            }
            "3" => {
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
            "4" => {
                if store.entries.is_empty() {
                    println!("No accounts saved yet.");
                } else {
                    println!("\nSaved Accounts:");
                    for (i, name) in store.entries.keys().enumerate() {
                        println!("{}. {}", i + 1, name);
                    }
                }
            }
            "5" => {
                if let Err(e) = backup_codes(&store) {
                    println!("Backup error: {}", e);
                }
            }
            "6" => {
                if let Err(e) = restore_codes_interactive(&mut store) {
                    println!("Restore error: {}", e);
                } else {
                    encrypt_store(&path, &password, &store)?;
                }
            }
            "7" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid choice.."),
        }
    }

    Ok(())
}
