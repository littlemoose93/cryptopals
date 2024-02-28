pub fn aes_128_ecb(ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::set_1::hex_to_bytes;

    #[test]
    fn sample() {
        let file_path = "src/set_1/challenge_7/aes-128-ecb.txt";

        let mut ciphertext_b64 = String::new();
        std::fs::File::open(file_path)
            .unwrap()
            .read_to_string(&mut ciphertext_b64)
            .unwrap();
        ciphertext_b64.retain(|c| !c.is_whitespace());
        let ciphertext = hex_to_bytes(&ciphertext_b64).unwrap();
    }
}
