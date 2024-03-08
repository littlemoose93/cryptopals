//! Discovery of ECB hidden message with random prefix

use std::{collections::HashMap, iter::repeat};

use aes::{
    cipher::{generic_array::GenericArray, KeyInit},
    Aes128,
};

use crate::set_1::{aes_128_ecb_encrypt_in_place, base64_to_bytes};

use super::{challenge_11::random_aes_key, challenge_9::pkcs_7_in_place};

/// Build an ecb encryptor function that will use the same key every time.
///
/// A random (but constant) prefix is added before the attacker text
///
/// Every new call to const_ecb_encryptor will produce a new function the encypts under a different key
fn build_ecb_encryptor_with_changing_rand_prefix() -> impl for<'a> Fn(&'a [u8]) -> Vec<u8> {
    let key = random_aes_key();
    let hidden_message = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

    let exact_key = GenericArray::from(key);
    let cipher = Aes128::new(&exact_key);

    move |attacker_controlled| {
        let prefix_length = rand::random::<usize>() % 512;
        let prefix = (0..prefix_length)
            .into_iter()
            .map(|_| rand::random())
            .collect::<Vec<u8>>();

        let mut plain_text = prefix.clone();
        plain_text.extend_from_slice(&attacker_controlled);
        plain_text.extend_from_slice(&hidden_message);

        pkcs_7_in_place(&mut plain_text, 16);
        aes_128_ecb_encrypt_in_place(&mut plain_text, &cipher).unwrap();
        plain_text
    }
}

/// Probes ciphertexts for hidden messages with some controlled input
///
/// Encrypting function is assumed to be of the form:
///     ECB(random-string || attacker-controlled-string || hidden-message) -> Ciphertext
///
/// AES128 is used for testing but any crypto algorithm used in an electronic code book (ECB) can be broken
pub struct EcbProbe<F> {
    encrypt_method: F,
}

impl<F> EcbProbe<F> {
    /// Creates a new [EcbProbe]
    pub fn new(encrypt_method: F) -> Self {
        Self { encrypt_method }
    }
}

impl<F> EcbProbe<F>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    /// Finds the hidden message in the cipher test of the encrypt method
    ///
    /// Stops searching after block sizes of 'max_block_size' bytes
    ///
    /// Returning None indicates the message could not be recovered
    ///
    /// Method for finding the hidden message:
    ///   1. Find block size
    ///   2. Build a probe map, allowing us to known how long the rand prefix (mod block size) was and gain new information on most probs  
    pub fn probe(&self, max_block_size: usize) -> Option<String> {
        let block_size = self.find_block_size(max_block_size)?;
        let probe_map = self.build_probe_map(block_size)?;

        todo!()
    }

    /// Finds the block size (in bytes)
    ///
    /// Stops searching after block sizes of 'max_block_size' bytes
    ///
    /// Returning None indicates the block size, if it exists, is less than 8 bytes or greater than 'max_block_size'
    pub fn find_block_size(&self, max_block_size: usize) -> Option<usize> {
        // Will generate repeated blocks in the cipher text
        let sample = Vec::from_iter(repeat(0u8).take(3 * max_block_size));
        let cipher_text = (self.encrypt_method)(&sample);

        for probe_block_size in 8..=1024 {
            // Ciphertext is not an integer multiple of the block length so we dont need any more checks
            if cipher_text.len() % probe_block_size > 0 {
                continue;
            }

            // Search for two adjacent blocks that are the same
            for start_idx in
                (0..(cipher_text.len() - 2 * probe_block_size)).step_by(probe_block_size)
            {
                let start_block = &cipher_text[start_idx..(start_idx + probe_block_size)];
                let next_block = &cipher_text
                    [(start_idx + probe_block_size)..(start_idx + 2 * probe_block_size)];

                if start_block == next_block {
                    return Some(probe_block_size);
                }
            }
        }
        None
    }

    /// Builds a HashMap of code blocks
    ///
    /// only works on blocksize upto u8::MAX
    fn build_probe_map(&self, block_size: usize) -> Option<ProbeMap> {
        // base should not contain any numbers that are going to be used to mark the beginning of the attack controlled vector
        // TODO update to work for larger block sizes
        let base = (1..((block_size + 1) as u8)).into_iter().cycle();
        let base_vector = base.clone().take(block_size).collect();

        let mut map = HashMap::new();
        let marker = repeat(0).take(block_size * 3).collect::<Vec<u8>>();
        for offset in 0..block_size {
            let mut offest_sample = marker.clone();
            // Note this_probe could be extended to give us a better chance of finding a new offset on every encrypt call
            let this_probe = base
                .clone()
                .skip(offset)
                .take(3 * block_size)
                .collect::<Vec<u8>>();

            offest_sample.extend(this_probe);

            let mut probe_key = None;
            while probe_key.is_none() {
                // Add rand previx incase we are not byte aligned or underlying prefix doesnt span a block
                // Note random sample is at less than the length of one block

                let mut this_sample: Vec<u8> = repeat(255)
                    .take(rand::random::<usize>() % block_size)
                    .collect();
                this_sample.extend_from_slice(&offest_sample);

                let cipher_text = (self.encrypt_method)(&this_sample);
                // find last marker block in cipher_text
                for start in (0..(cipher_text.len() - 2 * block_size)).step_by(block_size) {
                    // found first marker block
                    if cipher_text[start..(start + block_size)]
                        == cipher_text[(start + block_size)..(start + 2 * block_size)]
                    {
                        if cipher_text[start..(start + block_size)]
                            == cipher_text[(start + 2 * block_size)..(start + 3 * block_size)]
                        {
                            continue;
                        }
                        let probe_start = start + 2 * block_size;
                        if cipher_text[probe_start..(probe_start + block_size)]
                            == cipher_text
                                [(probe_start + block_size)..(probe_start + 2 * block_size)]
                        {
                            probe_key =
                                Some(cipher_text[probe_start..(probe_start + block_size)].to_vec());
                        }

                        break;
                    }
                }
            }

            let probe_key = probe_key.unwrap();
            map.insert(probe_key, offset);
        }

        Some(ProbeMap {
            base: base_vector,
            map,
        })
    }
}

#[derive(Debug)]
struct ProbeMap {
    /// The zero offset probe
    base: Vec<u8>,
    /// Map of all encrypted cyclic permutations of base to the cyclic offset from the base vector
    map: HashMap<Vec<u8>, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Used for running samples"]
    fn sample() {
        // Blocksize is 16;
        let encrypt_method = build_ecb_encryptor_with_changing_rand_prefix();
        let ecb_probe = EcbProbe::new(encrypt_method);

        let block_size = ecb_probe.probe(1024).unwrap();

        // assert_eq!(block_size, 16)
    }

    #[test]
    fn find_block_size_is_ecb() {
        // Blocksize is 16;
        let encrypt_method = build_ecb_encryptor_with_changing_rand_prefix();
        let ecb_probe = EcbProbe::new(encrypt_method);

        let block_size = ecb_probe.find_block_size(1024).unwrap();
        assert_eq!(block_size, 16)
    }

    #[test]
    fn build_probe_map() {
        // Blocksize is 16;
        let encrypt_method = build_ecb_encryptor_with_changing_rand_prefix();
        let ecb_probe = EcbProbe::new(encrypt_method);

        let probe_map = ecb_probe.build_probe_map(16).unwrap();
        let probe_map_values = probe_map
            .map
            .values()
            .map(Clone::clone)
            .collect::<Vec<usize>>();
        for offset in 0..15 {
            assert!(
                probe_map_values.contains(&offset),
                "Missing offset = {offset}"
            );
        }
        assert_eq!(probe_map_values.len(), 16);
    }
}
