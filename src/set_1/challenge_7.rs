use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit},
    Aes128,
};

//
pub fn aes_128_ecb(ciphertext: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let exact_key = GenericArray::from(*key);

    for chunk in ciphertext.chunks(16) {
        let chunk_array: [u8; 16] = chunk.try_into().unwrap();
        let mut block = GenericArray::from(chunk_array);
        let cipher = Aes128::new(&exact_key);
        cipher.decrypt_block(&mut block);
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

        let plain_text = aes_128_ecb(&ciphertext, key.try_into().unwrap()).unwrap();

        println!("{}", String::from_utf8_lossy(&plain_text));
        assert!(false);
    }
}
