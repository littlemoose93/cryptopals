use std::io::Read;

use crate::set_1::xor_repeat;

use super::{break_single_char_xor, hex_to_bytes, score_plain_text};

/// Returns the key and encrypted text for the single line in the file that is encrypted
// Might want to rework the method input here?
pub fn find_encrypted_line(file_path: &str) -> (u8, String) {
    let mut file = std::fs::File::open(file_path).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();

    let mut best_key = 0;
    let mut best_score = f64::MAX;
    let mut best_text = String::new();

    for line in content.lines() {
        let line_bytes = hex_to_bytes(line).unwrap();
        let key = break_single_char_xor(&line_bytes);

        let decrypted_text = xor_repeat(&line_bytes, &[key]).unwrap();
        let score = score_plain_text(&decrypted_text);
        if score < best_score {
            best_score = score;
            best_key = key;
            best_text = String::from_utf8_lossy(&decrypted_text).into();
        }
    }

    (best_key, best_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_line() {
        let file_path = "src/set_1/challenge_4/maybe_encrypted_lines.txt";
        println!("{:?}", std::env::current_dir().unwrap());
        let (key, text) = find_encrypted_line(file_path);
        println!("key: {key} ({})", key as char);
        println!("Decrypted Text: {}", text);
        // Values recovered from previous decryption
        assert_eq!(key, 53);
        assert_eq!(&text, "Now that the party is jumping\n");
    }
}
