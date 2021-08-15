#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7() {
        assert_eq!(
            pkcs7(b"YELLOW SUBMARINE", 20).unwrap(),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }
    #[test]
    fn test_remove_pkcs7_legit_input() {
        assert_eq!(
            remove_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04").unwrap(),
            b"ICE ICE BABY"
        );
    }

    #[test]
    fn test_remove_pkcs7_error_input() {
        assert_eq!(
            remove_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05"),
            Err(Pkcs7ParsingError::InvalidArgument)
        );

        assert_eq!(
            remove_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04"),
            Err(Pkcs7ParsingError::InvalidArgument)
        );
    }
}
pub fn pkcs7(data: &[u8], block_length: usize) -> Option<Vec<u8>> {
    let pad_length = block_length - data.len() % block_length;
    if pad_length > u8::MAX as usize {
        return None;
    }

    let mut padded_data: Vec<u8> = Vec::new();
    padded_data.append(&mut data.to_vec());
    padded_data.append(&mut vec![pad_length as u8; pad_length]);

    return Some(padded_data);
}

#[derive(Debug, PartialEq)]
pub enum Pkcs7ParsingError {
    InvalidArgument,
}

fn validate_pkcs7(data: &[u8]) -> Result<u8, Pkcs7ParsingError> {
    let pad_length = data.last().ok_or(Pkcs7ParsingError::InvalidArgument)?;
    if *pad_length > 16 {
        return Err(Pkcs7ParsingError::InvalidArgument);
    }
    if data[data.len() - *pad_length as usize..].to_vec() != vec![*pad_length; *pad_length as usize]
    {
        return Err(Pkcs7ParsingError::InvalidArgument);
    }

    Ok(*pad_length)
}

pub fn remove_pkcs7(data: &[u8]) -> Result<Vec<u8>, Pkcs7ParsingError> {
    let pad_length = validate_pkcs7(data)?;

    let mut unpadded_data: Vec<u8> = Vec::new();
    unpadded_data.append(&mut data[..data.len() - pad_length as usize].to_vec());

    return Ok(unpadded_data);
}
