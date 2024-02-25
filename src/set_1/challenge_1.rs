use base64::Engine;

// Converts a hex string to bytes
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();

    for byte in s.as_bytes().chunks_exact(2) {
        let composit_value = char_to_byte(byte[0])? << 4 | char_to_byte(byte[1])?;
        out.push(composit_value);
    }

    Some(out)
}

/// Converts bytes into a base64 encoded string
pub fn bytes_to_base64(v: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

/// Converts bytes into a base64 encoded string
pub fn base64_to_bytes(v: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(v).unwrap()
}

fn char_to_byte<C: Into<char>>(c: C) -> Option<u8> {
    match c.into() {
        '0' => Some(0),
        '1' => Some(1),
        '2' => Some(2),
        '3' => Some(3),
        '4' => Some(4),
        '5' => Some(5),
        '6' => Some(6),
        '7' => Some(7),
        '8' => Some(8),
        '9' => Some(9),
        'a' => Some(10),
        'b' => Some(11),
        'c' => Some(12),
        'd' => Some(13),
        'e' => Some(14),
        'f' => Some(15),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_base_64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = hex_to_bytes(hex).unwrap();
        let hex_as_b64 = bytes_to_base64(&bytes);
        assert_eq!(expected_base64, hex_as_b64);
    }

    mod hex_to_bytes {
        use super::*;

        #[test]
        fn zero() {
            let hex = "00";
            let expected_bytes = vec![0];
            let bytes = hex_to_bytes(hex).unwrap();
            assert_eq!(expected_bytes, bytes);
        }

        #[test]
        fn max() {
            let hex = "ff";
            let expected_bytes = vec![255];
            let bytes = hex_to_bytes(hex).unwrap();
            assert_eq!(expected_bytes, bytes);
        }

        #[test]
        fn fifteen() {
            let hex = "0f";
            let bytes = hex_to_bytes(hex).unwrap();
            let expected_bytes = vec![15];
            assert_eq!(expected_bytes, bytes);
        }

        #[test]
        fn two_fourty() {
            let hex = "f0";
            let bytes = hex_to_bytes(hex).unwrap();
            let expected_bytes = vec![240];
            assert_eq!(expected_bytes, bytes);
        }
    }
}
