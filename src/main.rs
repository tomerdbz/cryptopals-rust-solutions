fn main() {
    let decoded_data = base64::decode(
        std::fs::read_to_string("/home/tc/cryptopals/hellorust/6.txt")
            .unwrap()
            .replace("\n", ""),
    )
    .unwrap();
    let keys = crypto::xor::break_repeating_xor(&decoded_data, Some(4));
    println!("{}", String::from_utf8(keys[0].clone()).unwrap());
    let decrypted_data = crypto::xor::apply_repeating_xor(&decoded_data, &keys[0]);
    println!("{}", String::from_utf8(decrypted_data).unwrap());
}
