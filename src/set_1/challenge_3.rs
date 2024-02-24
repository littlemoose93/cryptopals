use std::collections::HashMap;

use super::xor_repeat;

/// Breaks single character ciphers and returns the key
pub fn break_single_char_xor(ciphertext: &[u8]) -> u8 {
    let mut best_key = 0;
    let mut best_score = f64::MAX;
    for candidate in 0..=255u8 {
        let plain_text = xor_repeat(&ciphertext, &[candidate]).unwrap();

        let score = score_plain_text(&plain_text);
        // println!(
        //     "{candidate} ({score}):  {}",
        //     String::from_utf8_lossy(&plain_text)
        // );

        if score < best_score {
            best_score = score;
            best_key = candidate;
        }
    }

    best_key
}

/// Scores a plain text message for how "english" it is
pub fn score_plain_text(txt: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(txt);
    let mut counts: HashMap<char, f64> = HashMap::new();

    let mut total_counts = 0.0;
    for c in text.chars() {
        *counts.entry(c.to_ascii_lowercase()).or_default() += 1.0;
        total_counts += 1.0;
    }

    // Add space to help with english phrases
    let expected_occurances: HashMap<char, f64> = vec![
        (' ', 0.1),
        ('e', 0.1116),
        ('a', 0.0849),
        ('r', 0.0758),
        ('i', 0.07544),
        ('o', 0.0754),
        ('t', 0.0695),
        ('n', 0.0665),
        ('s', 0.0573),
        ('l', 0.0549),
        ('c', 0.0453),
        ('u', 0.0363),
        ('d', 0.0338),
        ('p', 0.0316),
        ('m', 0.0301),
        ('h', 0.0300),
        ('g', 0.0247),
        ('b', 0.0207),
        ('f', 0.0181),
        ('y', 0.0178),
        ('w', 0.0129),
        ('k', 0.0110),
        ('v', 0.0101),
        ('x', 0.0029),
        ('z', 0.0027),
        ('j', 0.0019),
        ('q', 0.0019),
    ]
    .into_iter()
    .collect();

    let mut score = 0.0;
    for c in 0..=255u8 {
        let expected_rate = expected_occurances.get(&c.into()).cloned().unwrap_or(0.0);
        let observed_count = counts.get(&c.into()).cloned().unwrap_or(0.0);
        score += (expected_rate - observed_count / total_counts).abs()
    }

    score
}

#[cfg(test)]
mod tests {
    use crate::set_1::hex_to_bytes;

    use super::*;

    #[test]
    fn sample_text() {
        let ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        // Manually decrypted the text with the key
        let expected_decrypted_message = "Cooking MC's like a pound of bacon";
        let expected_key = 'X';

        let ciphertext_bytes = hex_to_bytes(ciphertext_hex).unwrap();
        let key = break_single_char_xor(&ciphertext_bytes);

        let decrypted_bytes = xor_repeat(&ciphertext_bytes, &[key]).unwrap();
        println!("key: {key} ({})", key as char);
        println!("Score: {}", score_plain_text(&decrypted_bytes));
        println!("Result: {}", String::from_utf8_lossy(&decrypted_bytes));

        assert_eq!(expected_key, key.into());
        assert_eq!(
            expected_decrypted_message,
            &String::from_utf8_lossy(&decrypted_bytes)
        );
    }
}
