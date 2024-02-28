use super::{break_single_char_xor, score_plain_text, xor_repeat};

pub fn break_repeated_xor(ciphertext: &[u8], min_key_size: usize, max_key_size: usize) -> Vec<u8> {
    let key_sizes_to_check = 3;
    let key_size = find_best_key_size(ciphertext, min_key_size, max_key_size, key_sizes_to_check);

    let mut best_text_score = f64::MAX;
    let mut best_key = Vec::new();

    for ks in key_size {
        let maybe_key = find_key_of_size_n(ciphertext, ks);
        let decrypted_text = xor_repeat(&ciphertext, &maybe_key).unwrap();
        let score = score_plain_text(&decrypted_text);

        if score < best_text_score {
            best_text_score = score;
            best_key = maybe_key;
        }
    }

    best_key
}

fn find_key_of_size_n(ciphertext: &[u8], key_size: usize) -> Vec<u8> {
    let mut key = Vec::new();

    for i in 0..key_size {
        let cipher_subsample: Vec<u8> = ciphertext
            .iter()
            .skip(i)
            .step_by(key_size)
            .map(|i| *i)
            .collect();
        let key_i = break_single_char_xor(&cipher_subsample);
        key.push(key_i);
    }

    key
}

fn find_best_key_size(
    ciphertext: &[u8],
    min_key_size: usize,
    max_key_size: usize,
    candidates: usize,
) -> Vec<usize> {
    let mut key_scores = Vec::new();

    for k in min_key_size..=max_key_size {
        let k_score = score_key_size(ciphertext, k);
        key_scores.push((k, k_score));
    }
    key_scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    key_scores.iter().take(candidates).map(|a| a.0).collect()
}

fn score_key_size(ciphertext: &[u8], key_size: usize) -> f64 {
    let samples = 5;
    let mut total_distance = 0;

    for sample in ciphertext.chunks(key_size * 2).take(samples) {
        let a = &sample[..key_size];
        let b = &sample[key_size..(2 * key_size)];
        total_distance += hamming_distance(a, b).unwrap();
    }

    f64::from(total_distance) / f64::from((key_size * samples) as u32)
}

/// Distance between two slices of different lengths
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<u32> {
    if a.len() != b.len() {
        return None;
    }

    let distance = a
        .into_iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum();

    Some(distance)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::set_1::{base64_to_bytes, xor_repeat};

    use super::*;

    #[test]
    fn breaking_bad() {
        let file_path = "src/set_1/challenge_6/encrypted_file.txt";
        let mut ciphertext_b64 = String::new();
        std::fs::File::open(file_path)
            .unwrap()
            .read_to_string(&mut ciphertext_b64)
            .unwrap();
        ciphertext_b64.retain(|c| !c.is_whitespace());

        let ciphertext = base64_to_bytes(&ciphertext_b64);
        let min_key_size = 1;
        let max_key_size = 40;
        let key = break_repeated_xor(&ciphertext, min_key_size, max_key_size);

        let decrypted_text = xor_repeat(&ciphertext, &key).unwrap();

        println!("{}", String::from_utf8_lossy(&decrypted_text));
        println!("Key ({}): {key:?}", key.len());
        println!("Key=\"{}\"", String::from_utf8_lossy(&key));
        // Prior decryption
        assert_eq!(
            "Terminator X: Bring the noise",
            String::from_utf8_lossy(&key)
        );
    }

    #[test]
    fn sample_hamming_distance() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        let expected_distance = 37;

        let distance = hamming_distance(a.as_bytes(), b.as_bytes()).unwrap();
        assert_eq!(expected_distance, distance);
    }

    mod hamming_distance_study {
        use rand::Rng;

        use super::*;

        #[test]
        #[ignore = "Not a test"]
        fn average_hamming_distance_with_xor() {
            let samples = 100000;
            let mut total_distance = 0;
            for _ in 0..samples {
                let a = rand_char();
                // let b = rand_char();
                let b: u8 = rand::random();
                let c = rand_char();
                // let d = rand_char();
                let d: u8 = rand::random();

                let e = a ^ b;
                let f = c ^ d;
                total_distance += hamming_distance(&[e], &[f]).unwrap();
            }

            let average = f64::from(total_distance) / f64::from(samples);
            println!("Average hamming distance with xor: {average}");
            assert!(false);
        }

        #[test]
        #[ignore = "Not a test"]
        fn average_hamming_distance_without_xor() {
            let samples = 100000;
            let mut total_distance = 0;
            for _ in 0..samples {
                let a = rand_char();

                let c = rand_char();

                let e = a;
                let f = c;
                total_distance += hamming_distance(&[e], &[f]).unwrap();
            }

            let average = f64::from(total_distance) / f64::from(samples);
            println!("Average hamming distance without xor: {average}");
            assert!(false);
        }

        // Provbabaly need to sample with english letter frequency to get more accurate statistics
        fn rand_char() -> u8 {
            let samples = vec![
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
            ];

            let mut total_weight = 0.0;
            for w in samples.iter().map(|a| a.1) {
                total_weight += w;
            }

            let mut rng = rand::thread_rng();
            let selected = rng.gen_range(0.0..total_weight);

            let mut seen = 0.0;

            for (c, w) in samples {
                seen += w;
                if seen > selected {
                    return c as u8;
                }
            }

            ' ' as u8
        }
    }
}
