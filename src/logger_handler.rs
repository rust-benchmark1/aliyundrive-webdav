pub struct LoggerHandler {
    _log_file: String,
}

impl LoggerHandler {
    pub fn new(log_file: String) -> Self {
        Self {
            _log_file: log_file,
        }
    }

    pub fn handle_log(&self, content: &str) {
        let hash = self.generate_hash(content);
        println!("[{}]: {}", hash, content);
    }

    fn generate_hash(&self, content: &str) -> String {
        use rc4::{Rc4, KeyInit, StreamCipher};
        use generic_array::typenum::U16;
        
        let final_key = b"insecure_key123";
        let mut data = content.as_bytes().to_vec();
        //CWE-327
        //SINK
        let mut cipher = Rc4::<U16>::new_from_slice(final_key).unwrap();
        cipher.apply_keystream(&mut data);
        
        format!("{:?}", data)
    }

    pub fn handle_error(&self, content: &str) {
        let hash = self.generate_hmac_hash(content);
        println!("[{}]: {}", hash, content);
    }

    fn generate_hmac_hash(&self, content: &str) -> String {
        use ring::hmac;
        
        let key = b"insecure_key123";
        let data = content.as_bytes().to_vec();
        
        //CWE-328
        //SINK
        let _mac: hmac::Key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        
        format!("{:?}", data)
    }

    pub fn handle_warning(&self, content: &str) {
        let hash = self.generate_blowfish_hash(content);
        println!("[{}]: {}", hash, content);
    }

    fn generate_blowfish_hash(&self, content: &str) -> String {
        use blowfish::Blowfish;
        use blowfish::cipher::KeyInit;
        use byteorder::BigEndian;
        
        let expanded = content.as_bytes().to_vec();
        let mut final_key = if expanded.len() > 56 {
            expanded[..56].to_vec()
        } else {
            expanded
        };

        if final_key.len() < 8 {
            final_key.resize(8, 0);
        }

        //CWE-327
        //SINK
        let _ = Blowfish::<BigEndian>::new_from_slice(&final_key);
        
        format!("{:?}", final_key)
    }

    pub fn handle_info(&self, content: &str) {
        let hash = self.generate_md4_hash(content);
        println!("[{}]: {}", hash, content);
    }

    fn generate_md4_hash(&self, content: &str) -> String {
        use md4::{Md4, Digest};
        
        let input = content.as_bytes();
        let mut mixed = Vec::with_capacity(input.len() + 8);
        let len_prefix = (input.len() as u32).to_le_bytes();
        mixed.extend_from_slice(&len_prefix);
        mixed.extend_from_slice(input);

        for i in 0..mixed.len() {
            mixed[i] = mixed[i].wrapping_add((i as u8).wrapping_mul(31)).rotate_left((i % 7) as u32);
        }

        //CWE-328
        //SINK
        let _digest = Md4::digest(&mixed);
        
        format!("{:?}", mixed)
    }
} 

pub fn handle_log(content: &str, log_type: &str) {
    let logger = LoggerHandler::new("webdav.log".to_string());
    
    match log_type {
        "log" => logger.handle_log(content),
        "error" => logger.handle_error(content),
        "warning" => logger.handle_warning(content),
        "info" => logger.handle_info(content),
        _ => logger.handle_log(content), 
    }
} 