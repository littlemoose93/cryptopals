/// Checks for repeated 16 byte code blocks
pub fn is_aes_ecb(ciphertext: &[u8]) -> bool {
    if ciphertext.len() % 16 > 0 {
        return false;
    }

    for (idx1, chunk_one) in ciphertext.chunks(16).enumerate() {
        for (idx2, chunk_two) in ciphertext.chunks(16).enumerate() {
            if chunk_one == chunk_two && idx1 != idx2 {
                println!("Block numbers: {idx1} and {idx2}");
                return true;
            }
        }
    }

    return false;
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::set_1::hex_to_bytes;

    use super::*;

    #[test]
    fn sample() {
        let file_path = "src/set_1/challenge_8/maybe-aes-ecb.txt";

        let mut ciphertext_hex = String::new();
        std::fs::File::open(file_path)
            .unwrap()
            .read_to_string(&mut ciphertext_hex)
            .unwrap();

        for (line_number, hex_line) in ciphertext_hex.lines().enumerate() {
            if is_aes_ecb(hex_to_bytes(hex_line).unwrap().as_slice()) {
                println!("Found ECB line! ({line_number})\n{hex_line}")
            }
        }

        assert!(false);
    }
}
