use bcrypt::{BcryptError, DEFAULT_COST, hash, verify};

pub fn hash_password(password: &str) -> Result<String, BcryptError> {
    // Cost factor 12 - good balance security vs performance
    hash(password, DEFAULT_COST + 2)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, BcryptError> {
    verify(password, hash)
}
