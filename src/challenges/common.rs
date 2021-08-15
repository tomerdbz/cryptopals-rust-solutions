use crate::challenges;
use challenges::ecb;
use std::collections::HashMap;

#[derive(PartialEq, Debug)]
pub enum Mode {
    Ecb = 0,
    Cbc = 1,
}

pub fn detect_encryption_ecb_or_cbc(data: &[u8]) -> Mode {
    if ecb::detect_128_ecb(&[data]).len() != 0 {
        return Mode::Ecb;
    }
    return Mode::Cbc;
}

pub fn clean_duplicates(data: &[u8]) -> Vec<u8> {
    let mut sorted_data = data.to_vec();
    sorted_data.sort();
    let mut equal_elements = 1;
    let mut equal_elements_count = HashMap::new();
    for i in 0..sorted_data.len() - 1 {
        if sorted_data[i] == sorted_data[i + 1] {
            equal_elements += 1;
        } else {
            equal_elements_count.insert(equal_elements, sorted_data[i]);
            equal_elements = 1;
        }
    }
    let possible_duplicates = equal_elements_count.iter().min().unwrap().0;

    data[..data.len() / possible_duplicates].to_vec()
}
