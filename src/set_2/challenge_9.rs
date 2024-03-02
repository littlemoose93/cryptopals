//! PKCS#7 Padding

/// Applys padding to the input such that it the output is an integer multiple of the block_size
pub fn pkcs_7(input: &[u8], block_size: u8) -> Vec<u8> {
    let padding_byte = block_size - (input.len() % (block_size as usize)) as u8;
    let mut output = input.to_vec();

    for _ in 0..padding_byte {
        output.push(padding_byte);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yellow_submarine_block_20() {
        let input = "YELLOW SUBMARINE";
        let block_size = 20;
        let mut expected_padded_input = input.as_bytes().to_vec();
        expected_padded_input.extend_from_slice(&[4, 4, 4, 4]);

        let padded_input = pkcs_7(input.as_bytes(), block_size);
        assert_eq!(expected_padded_input, padded_input);
    }

    #[test]
    fn yellow_submarine_block_16() {
        let input = "YELLOW SUBMARINE";
        let block_size = 16;
        let mut expected_padded_input = input.as_bytes().to_vec();
        expected_padded_input.extend_from_slice(&[16; 16]);

        let padded_input = pkcs_7(input.as_bytes(), block_size);
        assert_eq!(expected_padded_input, padded_input);
    }

    #[test]
    fn yellow_submarine_block_17() {
        let input = "YELLOW SUBMARINE";
        let block_size = 17;
        let mut expected_padded_input = input.as_bytes().to_vec();
        expected_padded_input.extend_from_slice(&[1]);

        let padded_input = pkcs_7(input.as_bytes(), block_size);
        assert_eq!(expected_padded_input, padded_input);
    }
}
