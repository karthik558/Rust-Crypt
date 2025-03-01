use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author="karthik558", version, about="Simple file encryption tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Password for encryption
        #[arg(short, long)]
        password: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Password for decryption
        #[arg(short, long)]
        password: String,
    },
}

// Derive an AES key from a password using Argon2 with a specific salt
fn derive_key(password: &str, salt_string: &str) -> Result<[u8; 32]> {
    // Parse the salt string
    let salt = SaltString::from_b64(salt_string)
        .map_err(|e| anyhow!("Failed to parse salt: {}", e))?;
    
    // Configure Argon2 with default parameters
    let argon2 = Argon2::default();
    
    // Hash the password to derive a key
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
    
    // Extract the hash and ensure it's the right length
    let hash_unwrapped = password_hash.hash.unwrap();
    let hash_bytes = hash_unwrapped.as_bytes();
    
    let mut key = [0u8; 32];
    
    // Copy the hash into our key buffer (truncate or pad as needed)
    let len = std::cmp::min(hash_bytes.len(), key.len());
    key[..len].copy_from_slice(&hash_bytes[..len]);
    
    Ok(key)
}

// Generate a new salt and encode it as a B64 string
fn generate_salt() -> String {
    let salt = SaltString::generate(&mut OsRng);
    salt.as_str().to_string()
}

// Encrypt file content
fn encrypt(content: &[u8], password: &str) -> Result<Vec<u8>> {
    // Generate a salt
    let salt = generate_salt();
    
    // Derive key from password using the salt
    let key_bytes = derive_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new(key);
    
    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the content
    let encrypted_content = cipher.encrypt(&nonce, content)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    // Store the salt length as a 4-byte value
    let salt_bytes = salt.as_bytes();
    let salt_len = salt_bytes.len() as u32;
    let salt_len_bytes = salt_len.to_le_bytes();
    
    // Combine all components:
    // Format: [salt_len(4 bytes)][salt][nonce(12 bytes)][encrypted data]
    let mut result = Vec::new();
    result.extend_from_slice(&salt_len_bytes);
    result.extend_from_slice(salt_bytes);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted_content);
    
    Ok(result)
}

// Decrypt file content
fn decrypt(encrypted_content: &[u8], password: &str) -> Result<Vec<u8>> {
    // Ensure the content is long enough for minimal header (4 bytes salt length + at least 1 byte salt + 12 bytes nonce)
    if encrypted_content.len() < 17 {
        return Err(anyhow!("Encrypted content is too short"));
    }
    
    // Extract the salt length (first 4 bytes)
    let mut salt_len_bytes = [0u8; 4];
    salt_len_bytes.copy_from_slice(&encrypted_content[0..4]);
    let salt_len = u32::from_le_bytes(salt_len_bytes) as usize;
    
    // Verify the content is long enough to contain the salt
    if encrypted_content.len() < 4 + salt_len + 12 {
        return Err(anyhow!("Encrypted content is too short to contain salt and nonce"));
    }
    
    // Extract the salt
    let salt_bytes = &encrypted_content[4..4+salt_len];
    let salt = std::str::from_utf8(salt_bytes)
        .map_err(|e| anyhow!("Failed to parse salt as UTF-8: {}", e))?;
    
    // Extract the nonce
    let nonce_bytes = &encrypted_content[4+salt_len..4+salt_len+12];
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // The rest is the actual encrypted data
    let actual_content = &encrypted_content[4+salt_len+12..];
    
    // Derive key from password using the same salt
    let key_bytes = derive_key(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new(key);
    
    // Decrypt the content
    let decrypted_content = cipher.decrypt(nonce, actual_content)
        .map_err(|e| anyhow!("Decryption failed - incorrect password or corrupted data: {}", e))?;
    
    Ok(decrypted_content)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Encrypt { input, output, password } => {
            // Read input file
            println!("Reading file: {}", input.display());
            let mut file = fs::File::open(input)
                .map_err(|e| anyhow!("Failed to open input file {}: {}", input.display(), e))?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .map_err(|e| anyhow!("Failed to read input file: {}", e))?;
            
            // Encrypt content
            println!("Encrypting...");
            let encrypted = encrypt(&content, password)?;
            
            // Write encrypted content to output file
            println!("Writing encrypted data to: {}", output.display());
            let mut output_file = fs::File::create(output)
                .map_err(|e| anyhow!("Failed to create output file {}: {}", output.display(), e))?;
            output_file.write_all(&encrypted)
                .map_err(|e| anyhow!("Failed to write to output file: {}", e))?;
            
            println!("✅ File encrypted successfully!");
        },
        Command::Decrypt { input, output, password } => {
            // Read encrypted file
            println!("Reading encrypted file: {}", input.display());
            let mut file = fs::File::open(input)
                .map_err(|e| anyhow!("Failed to open encrypted file {}: {}", input.display(), e))?;
            let mut encrypted_content = Vec::new();
            file.read_to_end(&mut encrypted_content)
                .map_err(|e| anyhow!("Failed to read encrypted file: {}", e))?;
            
            // Decrypt content
            println!("Decrypting...");
            let decrypted = decrypt(&encrypted_content, password)?;
            
            // Write decrypted content to output file
            println!("Writing decrypted data to: {}", output.display());
            let mut output_file = fs::File::create(output)
                .map_err(|e| anyhow!("Failed to create output file {}: {}", output.display(), e))?;
            output_file.write_all(&decrypted)
                .map_err(|e| anyhow!("Failed to write to output file: {}", e))?;
            
            println!("✅ File decrypted successfully!");
        }
    }

    Ok(())
}