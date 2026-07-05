// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::{aead, keys};
use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;
use crate::secrets::{MasterKey32, SecByte12, SecByte32, SecretBytes, SecretFixedBytes};

const KEYFILE_MAGIC: &[u8; 4] = b"KEYF";
const KEYFILE_VERSION: u8 = 1;
const ALG_ID_AES256_GCM_SIV: u8 = 1;
const DEK_LEN: u16 = 32;
const KEYFILE_KEK_INFO: &[u8] = b"kek/v1";
const MAX_KEYFILE_SIZE: u64 = 64 * 1024;
const CT_WRAP_LEN: usize = 48;

#[inline]
pub fn read_keyfile_bytes(path: &Path) -> Result<SecretBytes> {
    let meta = fs::symlink_metadata(path).map_err(LithiumError::io)?;
    check_keyfile_metadata(&meta)?;
    Ok(SecretBytes::new(fs::read(path).map_err(LithiumError::io)?))
}

fn check_keyfile_metadata(meta: &fs::Metadata) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(LithiumError::invalid_perms("keyfile_is_symlink"));
    }
    if !meta.is_file() {
        return Err(LithiumError::invalid_perms("keyfile_not_regular_file"));
    }
    if meta.len() > MAX_KEYFILE_SIZE {
        return Err(LithiumError::invalid_len(
            MAX_KEYFILE_SIZE as usize,
            meta.len() as usize,
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(LithiumError::invalid_perms(
                "keyfile_group_or_world_accessible",
            ));
        }
    }
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(LithiumError::invalid_perms("keystore_dir_not_directory"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(LithiumError::invalid_perms(
                        "keystore_dir_group_or_world_accessible",
                    ));
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(path).map_err(LithiumError::io)
        }
        Err(e) => Err(LithiumError::io(e)),
    }
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
            hex::encode(suffix.expose_as_slice())
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

/// Atomically writes `data` via a private tmp file + `rename`, with `fsync` on
/// the file (and, on Unix, the parent directory).
///
/// Unix: the tmp file is created `0o600`, so the keyfile is owner-only from
/// creation. Windows: no DACL is set, the file inherits the parent directory's
/// ACL. Keep the store under a per-user profile directory (owner-only by
/// default) or protect the master key with a sealing `MkProvider`; the
/// built-in plaintext provider is dev-only regardless.
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

pub fn write_secure_new(path: &Path, data: &[u8]) -> Result<()> {
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

    let link_res = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    link_res.map_err(LithiumError::io)?;

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
    let hk = Hkdf::<Sha256>::new(Some(salt), mk.expose_as_slice());
    let mut out = SecByte32::new_zeroed();
    hk.expand(KEYFILE_KEK_INFO, out.expose_as_mut_slice())?;
    Ok(out)
}

#[inline]
fn wrap_dek(kek: &SecByte32, dek: &SecByte32, aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(dek.expose_as_slice()),
        kek,
        &nonce,
        aad,
    )?;

    Ok((ct.as_slice().to_vec(), *nonce.expose_as_array()))
}

#[inline]
fn encrypt_payload(dek: &SecByte32, payload: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(&SecretBytes::from_slice(payload), dek, &nonce, aad)?;

    Ok((ct.as_slice().to_vec(), *nonce.expose_as_array()))
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

fn take<'a>(buf: &'a [u8], idx: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = idx
        .checked_add(len)
        .ok_or_else(LithiumError::malformed_keyfile)?;
    let slice = buf
        .get(*idx..end)
        .ok_or_else(LithiumError::malformed_keyfile)?;
    *idx = end;
    Ok(slice)
}

fn read_u16(buf: &[u8], idx: &mut usize) -> Result<u16> {
    let b = take(buf, idx, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], idx: &mut usize) -> Result<u32> {
    let b = take(buf, idx, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
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
    let dek_len = read_u16(buf, &mut idx)?;

    let len_salt = read_u16(buf, &mut idx)? as usize;
    if len_salt != 32 {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(take(buf, &mut idx, 32)?);

    let len_nonce_wrap = read_u16(buf, &mut idx)? as usize;
    if len_nonce_wrap != 12 {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut nonce_wrap = [0u8; 12];
    nonce_wrap.copy_from_slice(take(buf, &mut idx, 12)?);

    let len_ct_wrap = read_u16(buf, &mut idx)? as usize;
    if len_ct_wrap != CT_WRAP_LEN {
        return Err(LithiumError::malformed_keyfile());
    }
    let ct_wrap = take(buf, &mut idx, len_ct_wrap)?.to_vec();

    let len_nonce_payload = read_u16(buf, &mut idx)? as usize;
    if len_nonce_payload != 12 {
        return Err(LithiumError::malformed_keyfile());
    }
    let mut nonce_payload = [0u8; 12];
    nonce_payload.copy_from_slice(take(buf, &mut idx, 12)?);

    let len_ct_payload = read_u32(buf, &mut idx)? as usize;
    let ct_payload = take(buf, &mut idx, len_ct_payload)?.to_vec();
    if idx != buf.len() {
        return Err(LithiumError::malformed_keyfile());
    }

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

fn encode_encrypted(mk: &MasterKey32, payload: &[u8], key_type: &str) -> Result<Vec<u8>> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.expose_as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload, &aad)?;

    Ok(build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.expose_as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    ))
}

pub fn save_secret32_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &SecretFixedBytes<32>,
    key_type: &str,
) -> Result<()> {
    write_secure(
        path,
        &encode_encrypted(mk, payload.expose_as_slice(), key_type)?,
    )
}

pub fn save_secret32_encrypted_new(
    path: &Path,
    mk: &MasterKey32,
    payload: &SecretFixedBytes<32>,
    key_type: &str,
) -> Result<()> {
    write_secure_new(
        path,
        &encode_encrypted(mk, payload.expose_as_slice(), key_type)?,
    )
}

pub fn save_bytes_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &[u8],
    key_type: &str,
) -> Result<()> {
    write_secure(path, &encode_encrypted(mk, payload, key_type)?)
}

pub fn save_bytes_encrypted_new(
    path: &Path,
    mk: &MasterKey32,
    payload: &[u8],
    key_type: &str,
) -> Result<()> {
    write_secure_new(path, &encode_encrypted(mk, payload, key_type)?)
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
    let kek_new = derive_kek(new_mk, salt_new.expose_as_array())?;
    let (ct_wrap_new, nonce_wrap_new) = wrap_dek(&kek_new, &dek, &aad)?;

    let out = build_record(
        version,
        alg_id,
        dek_len,
        salt_new.expose_as_array(),
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

    #[test]
    fn trailing_garbage_is_rejected() {
        let rec = build_record(
            KEYFILE_VERSION,
            ALG_ID_AES256_GCM_SIV,
            DEK_LEN,
            &[0x33u8; 32],
            &[0x44u8; 12],
            &[0x55u8; 48],
            &[0x66u8; 12],
            &[0x77u8; 40],
        );

        parse_keyfile(&SecretBytes::new(rec.clone())).expect("canonical record must parse");

        for extra in [&b"\x00"[..], b"garbage", &[0u8; 64][..]] {
            let mut tampered = rec.clone();
            tampered.extend_from_slice(extra);
            assert!(
                parse_keyfile(&SecretBytes::new(tampered)).is_err(),
                "a record with {} trailing bytes must be rejected",
                extra.len()
            );
        }
    }

    #[test]
    fn wrong_ct_wrap_len_is_rejected() {
        let rec = build_record(
            KEYFILE_VERSION,
            ALG_ID_AES256_GCM_SIV,
            DEK_LEN,
            &[0x33u8; 32],
            &[0x44u8; 12],
            &[0x55u8; 47],
            &[0x66u8; 12],
            &[0x77u8; 40],
        );
        assert!(parse_keyfile(&SecretBytes::new(rec)).is_err());
    }

    #[test]
    fn oversize_keyfile_is_rejected() {
        let dir = std::env::temp_dir().join(format!("lithium-oversize-{}", std::process::id()));
        let path = dir.join("big.keyf");
        write_secure(&path, &vec![0u8; (MAX_KEYFILE_SIZE + 1) as usize]).unwrap();
        assert!(read_keyfile_bytes(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_keyfile_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lithium-perms-{}", std::process::id()));
        let path = dir.join("secret.keyf");
        write_secure(&path, b"payload").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_keyfile_bytes(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_keyfile_is_rejected() {
        let dir = std::env::temp_dir().join(format!("lithium-symlink-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.keyf");
        write_secure(&target, b"payload").unwrap();
        let link = dir.join("link.keyf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_keyfile_bytes(&link).is_err());
        let _ = fs::remove_dir_all(&dir);
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
