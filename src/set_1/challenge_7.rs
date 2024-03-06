use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

/// A very slow AES128-ECB decryptor
pub fn aes_128_ecb_decryt(ciphertext: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let exact_key = GenericArray::from(*key);

    let cipher = Aes128::new(&exact_key);
    for chunk in ciphertext.chunks(16) {
        let chunk_array: [u8; 16] = chunk.try_into().unwrap();
        let mut block = GenericArray::from(chunk_array);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(block.as_slice());
    }

    Some(out)
}

/// A very slow AES128-ECB encryptor
pub fn aes_128_ecb_encrypt(plain_text: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(plain_text.len());
    let exact_key = GenericArray::from(*key);
    let cipher = Aes128::new(&exact_key);

    for chunk in plain_text.chunks(16) {
        let chunk_array: [u8; 16] = chunk.try_into().unwrap();
        let mut block = GenericArray::from(chunk_array);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(block.as_slice());
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::set_1::base64_to_bytes;

    #[test]
    fn sample() {
        let file_path = "src/set_1/challenge_7/aes-128-ecb.txt";

        let mut ciphertext_b64 = String::new();
        std::fs::File::open(file_path)
            .unwrap()
            .read_to_string(&mut ciphertext_b64)
            .unwrap();
        ciphertext_b64.retain(|c| !c.is_whitespace());
        let ciphertext = base64_to_bytes(&ciphertext_b64);
        let key = "YELLOW SUBMARINE".as_bytes();

        let plain_text = aes_128_ecb_decryt(&ciphertext, key.try_into().unwrap()).unwrap();

        println!("{}", String::from_utf8_lossy(&plain_text));
        assert!(false);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let plain_text = [0; 48].to_vec();
        let key = [1; 16];

        let cipher_text = aes_128_ecb_encrypt(&plain_text, &key).unwrap();
        assert_ne!(cipher_text, plain_text);

        let decypted_plain_text = aes_128_ecb_decryt(&cipher_text, &key).unwrap();
        assert_eq!(plain_text, decypted_plain_text);
    }
}
