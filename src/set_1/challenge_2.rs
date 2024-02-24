/// Xors two slices of the same length together
pub fn xor_exact(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        return None;
    }

    Some(a.iter().zip(b.iter()).map(|(a_i, b_i)| a_i ^ b_i).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_1::hex_to_bytes;
    #[test]
    fn challenge_example() {
        let a = hex_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
        let b = hex_to_bytes("686974207468652062756c6c277320657965").unwrap();
        let expected_xor_result = hex_to_bytes("746865206b696420646f6e277420706c6179").unwrap();

        let xor_result = xor_exact(&a, &b).unwrap();
        assert_eq!(expected_xor_result, xor_result);
    }
}
