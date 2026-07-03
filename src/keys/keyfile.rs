// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::{aead, keys};
use crate::error::{ErrorKind, LithiumError, Result};
use crate::public::PublicBytes;
use crate::secrets::{MasterKey32, SecByte12, SecByte32, SecretBytes, SecretFixedBytes};

const KEYFILE_MAGIC: &[u8; 4] = b"KEYF";
const KEYFILE_VERSION: u8 = 1;
const ALG_ID_AES256_GCM_SIV: u8 = 1;
const DEK_LEN: u16 = 32;
const KEYFILE_KEK_INFO: &[u8] = b"kek/v1";

#[inline]
pub fn read_keyfile_bytes(path: &Path) -> Result<SecretBytes> {
    Ok(SecretBytes::new(fs::read(path).map_err(LithiumError::io)?))
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn create_private_tmp(path: &Path) -> Result<(fs::File, PathBuf)> {
    for _ in 0..8 {
        let suffix = keys::random_fixed::<8>()?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!(
            "tmp-{:x}-{:x}-{}",
            std::process::id(),
            seq,
            hex::encode(suffix.as_slice())
        ));

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        match opts.open(&tmp) {
            Ok(f) => return Ok((f, tmp)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(LithiumError::io(e)),
        }
    }

    Err(LithiumError::io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "keyfile tmp name not unique",
    )))
}

pub fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(LithiumError::io)?;
    }

    let (mut f, tmp) = create_private_tmp(path)?;

    let write_res = (|| -> Result<()> {
        f.write_all(data).map_err(LithiumError::io)?;
        f.sync_all().map_err(LithiumError::io)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, path).map_err(LithiumError::io)?;

    // fsync the dir too or the rename can vanish on a crash; best-effort, ignore errors
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let _ = fs::File::open(parent).and_then(|dir| dir.sync_all());
    }

    Ok(())
}

#[inline]
fn aad_for(version: u8, key_type: &str) -> Vec<u8> {
    format!("keyfile:v{}|{}", version, key_type).into_bytes()
}

#[inline]
fn derive_kek(mk: &MasterKey32, salt: &[u8; 32]) -> Result<SecByte32> {
    let hk = Hkdf::<Sha256>::new(Some(salt), mk.as_slice());
    let mut out = SecByte32::new_zeroed();
    hk.expand(KEYFILE_KEK_INFO, out.as_mut_slice())?;
    Ok(out)
}

#[inline]
fn wrap_dek(kek: &SecByte32, dek: &SecByte32, aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(&SecretBytes::from_slice(dek.as_slice()), kek, &nonce, aad)?;

    Ok((ct.as_slice().to_vec(), *nonce.as_array()))
}

#[inline]
fn encrypt_payload(dek: &SecByte32, payload: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(&SecretBytes::from_slice(payload), dek, &nonce, aad)?;

    Ok((ct.as_slice().to_vec(), *nonce.as_array()))
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    version: u8,
    alg_id: u8,
    dek_len: u16,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(KEYFILE_MAGIC);
    out.push(version);
    out.push(alg_id);
    out.extend_from_slice(&dek_len.to_be_bytes());

    out.extend_from_slice(&(salt.len() as u16).to_be_bytes());
    out.extend_from_slice(salt);

    out.extend_from_slice(&(nonce_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_wrap);

    out.extend_from_slice(&(ct_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(ct_wrap);

    out.extend_from_slice(&(nonce_payload.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_payload);

    out.extend_from_slice(&(ct_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(ct_payload);

    out
}

fn read_u16(buf: &[u8], idx: &mut usize) -> Result<u16> {
    if *idx + 2 > buf.len() {
        return Err(LithiumError::new(ErrorKind::InvalidLength {
            expected: *idx + 2,
            got: buf.len(),
        }));
    }
    let v = u16::from_be_bytes([buf[*idx], buf[*idx + 1]]);
    *idx += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], idx: &mut usize) -> Result<u32> {
    if *idx + 4 > buf.len() {
        return Err(LithiumError::new(ErrorKind::InvalidLength {
            expected: *idx + 4,
            got: buf.len(),
        }));
    }
    let v = u32::from_be_bytes([buf[*idx], buf[*idx + 1], buf[*idx + 2], buf[*idx + 3]]);
    *idx += 4;
    Ok(v)
}

#[allow(clippy::type_complexity)]
fn parse_keyfile(
    buf: &SecretBytes,
) -> Result<(u8, u8, u16, [u8; 32], [u8; 12], Vec<u8>, [u8; 12], Vec<u8>)> {
    let buf = buf.expose_as_slice();
    let mut idx = 0;

    if buf.len() < 8 {
        return Err(LithiumError::invalid_len(8, buf.len()));
    }
    if &buf[0..4] != KEYFILE_MAGIC {
        return Err(LithiumError::malformed_keyfile());
    }

    idx += 4;
    let version = buf[idx];
    idx += 1;
    let alg_id = buf[idx];
    idx += 1;
    let dek_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
    idx += 2;

    let len_salt = read_u16(buf, &mut idx)? as usize;
    if len_salt != 32 || idx + 32 > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[idx..idx + 32]);
    idx += 32;

    let len_nonce_wrap = read_u16(buf, &mut idx)? as usize;
    if len_nonce_wrap != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut nonce_wrap = [0u8; 12];
    nonce_wrap.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_wrap = read_u16(buf, &mut idx)? as usize;
    if idx + len_ct_wrap > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let ct_wrap = buf[idx..idx + len_ct_wrap].to_vec();
    idx += len_ct_wrap;

    let len_nonce_payload = read_u16(buf, &mut idx)? as usize;
    if len_nonce_payload != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut nonce_payload = [0u8; 12];
    nonce_payload.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_payload = read_u32(buf, &mut idx)? as usize;
    if idx + len_ct_payload > buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }
    let ct_payload = buf[idx..idx + len_ct_payload].to_vec();

    Ok((
        version,
        alg_id,
        dek_len,
        salt,
        nonce_wrap,
        ct_wrap,
        nonce_payload,
        ct_payload,
    ))
}

#[cfg(feature = "fuzzing")]
#[allow(clippy::type_complexity)]
pub fn parse_keyfile_fuzz(
    bytes: &[u8],
) -> Result<(u8, u8, u16, [u8; 32], [u8; 12], Vec<u8>, [u8; 12], Vec<u8>)> {
    parse_keyfile(&SecretBytes::new(bytes.to_vec()))
}

fn unwrap_dek(
    mk: &MasterKey32,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    aad: &[u8],
) -> Result<SecByte32> {
    let kek = derive_kek(mk, salt)?;
    let nonce = SecByte12::from_slice(nonce_wrap)?;
    let dek_bytes = aead::decrypt_raw(&PublicBytes::from_slice(ct_wrap), &kek, &nonce, aad)?;
    SecByte32::from_slice(dek_bytes.expose_as_slice())
}

fn decrypt_payload_bytes(
    dek: &SecByte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &[u8],
) -> Result<SecretBytes> {
    let nonce = SecByte12::from_slice(nonce_payload)?;
    aead::decrypt_raw(&PublicBytes::from_slice(ct_payload), dek, &nonce, aad)
}

fn decrypt_payload_32(
    dek: &SecByte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &[u8],
) -> Result<SecretFixedBytes<32>> {
    let pt = decrypt_payload_bytes(dek, nonce_payload, ct_payload, aad)?;
    SecretFixedBytes::<32>::from_slice(pt.expose_as_slice())
}

pub fn save_secret32_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &SecretFixedBytes<32>,
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload.as_slice(), &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn save_bytes_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &[u8],
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload, &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn load_secret32_decrypted(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretFixedBytes<32>> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::malformed_keyfile());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_32(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn load_bytes_decrypted(path: &Path, mk: &MasterKey32, key_type: &str) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::malformed_keyfile());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_bytes(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn rewrap_keyfile_dek_to_bytes(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (
        version,
        alg_id,
        dek_len,
        salt_old,
        nonce_wrap_old,
        ct_wrap_old,
        nonce_payload,
        ct_payload,
    ) = parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::malformed_keyfile());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(old_mk, &salt_old, &nonce_wrap_old, &ct_wrap_old, &aad)?;

    let salt_new = keys::random_fixed::<32>()?;
    let kek_new = derive_kek(new_mk, salt_new.as_array())?;
    let (ct_wrap_new, nonce_wrap_new) = wrap_dek(&kek_new, &dek, &aad)?;

    let out = build_record(
        version,
        alg_id,
        dek_len,
        salt_new.as_array(),
        &nonce_wrap_new,
        &ct_wrap_new,
        &nonce_payload,
        &ct_payload,
    );

    Ok(SecretBytes::new(out))
}

pub fn rewrap_keyfile_dek(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<()> {
    let out = rewrap_keyfile_dek_to_bytes(path, old_mk, new_mk, key_type)?;
    write_secure(path, out.expose_as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_record_layout_is_pinned() {
        let salt = [0x33u8; 32];
        let nonce_wrap = [0x44u8; 12];
        let ct_wrap = [0x55u8; 48];
        let nonce_payload = [0x66u8; 12];
        let ct_payload = [0x77u8; 40];

        let rec = build_record(
            KEYFILE_VERSION,
            ALG_ID_AES256_GCM_SIV,
            DEK_LEN,
            &salt,
            &nonce_wrap,
            &ct_wrap,
            &nonce_payload,
            &ct_payload,
        );
        assert_eq!(
            hex::encode(&rec),
            "4b4559460101002000203333333333333333333333333333333333333333333333333333333333333333000c4444444444444444444444440030555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555000c6666666666666666666666660000002877777777777777777777777777777777777777777777777777777777777777777777777777777777"
        );

        let (v, alg, dl, s, nw, cw, np, cp) = parse_keyfile(&SecretBytes::new(rec)).unwrap();
        assert_eq!(v, KEYFILE_VERSION);
        assert_eq!(alg, ALG_ID_AES256_GCM_SIV);
        assert_eq!(dl, DEK_LEN);
        assert_eq!(s, salt);
        assert_eq!(nw, nonce_wrap);
        assert_eq!(cw, ct_wrap.to_vec());
        assert_eq!(np, nonce_payload);
        assert_eq!(cp, ct_payload.to_vec());
    }

    #[cfg(unix)]
    #[test]
    fn write_secure_creates_0600_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("lithium-keyfile-{}", std::process::id()));
        let path = dir.join("secret.keyf");

        write_secure(&path, b"top secret payload").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keyfile must be owner-only");
        assert_eq!(
            read_keyfile_bytes(&path).unwrap().expose_as_slice(),
            b"top secret payload"
        );
        assert!(
            fs::read_dir(&dir)
                .unwrap()
                .all(|e| { e.unwrap().file_name().to_string_lossy() == "secret.keyf" }),
            "no leftover tmp files"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
