#[cfg(test)]
mod tests {
    use crate::set_1::{hex_to_bytes, xor_repeat};

    #[test]
    fn encrypt_repeat() {
        let key = "ICE";
        let plain_text =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        let expected_encrypted_text_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let encrypted_bytes = xor_repeat(plain_text.as_bytes(), key.as_bytes()).unwrap();
        let expected_bytes = hex_to_bytes(expected_encrypted_text_hex).unwrap();
        assert_eq!(expected_bytes, encrypted_bytes);
    }
}
