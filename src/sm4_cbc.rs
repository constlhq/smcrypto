use cipher::block_padding::UnpadError;
use cipher::{Iv, Key};
use sm4::Sm4;
use sm4::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

type Sm4CbcEnc = cbc::Encryptor<Sm4>;
type Sm4CbcDec = cbc::Decryptor<Sm4>;

pub fn encrypt_cbc_padded(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut smt = Sm4CbcEnc::new(Key::<Sm4>::from_slice(&key), iv.into());
    smt.encrypt_padded_vec_mut::<Pkcs7>(&data)
}

pub fn decrypt_cbc_padded(key: &[u8], iv: &[u8], cipher: &[u8]) -> Result<Vec<u8>, UnpadError> {
    let mut smt = Sm4CbcDec::new(Key::<Sm4>::from_slice(&key), iv.into());
    smt.decrypt_padded_vec_mut::<Pkcs7>(&cipher)
}

pub fn decrypt_cbc_padded_mut<'a>(
    key: &[u8],
    cipher: &'a mut [u8],
) -> Result<&'a [u8], UnpadError> {
    let mut smt = Sm4CbcDec::new(Key::<Sm4>::from_slice(&key), cipher[..16].into());

    println!("====>cipher: {}", hex::encode(&cipher[16..]));
    smt.decrypt_padded_mut::<Pkcs7>(&mut cipher[16..])
}
