// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::ErrorKind;
use lithium_core::crypto::kdf::Argon2Params;
use lithium_core::opaque::server::ServerSetup;
use lithium_core::opaque::{client, server};
use lithium_core::secrets::{SecByte64, SecretString};

const CID: &[u8] = b"user-123";
const HANDLER: &[u8] = b"client-handle";
const SERVER: &[u8] = b"server.example";
const PWD: &str = "Correct-Horse-1!";

fn ss(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

fn is_malformed(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::MalformedInput { .. })
}

fn is_invalid_credentials(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::InvalidCredentials { .. })
}

fn register(setup: &ServerSetup, cid: &[u8], pwd: &str) -> (Vec<u8>, SecByte64) {
    let (req, cstate) = client::client_registration_start(&ss(pwd)).unwrap();
    let resp = server::server_registration_start(setup, &req, cid).unwrap();
    let (upload, export_key) = client::client_registration_finish(
        cstate,
        &resp,
        &ss(pwd),
        HANDLER,
        SERVER,
        Argon2Params::default(),
    )
    .unwrap();
    let record = server::server_registration_finish(&upload).unwrap();
    (record, export_key)
}

fn login(
    setup: &ServerSetup,
    record: &[u8],
    cid: &[u8],
    pwd: &str,
    handler: &[u8],
    server_id: &[u8],
) -> lithium_core::Result<SecByte64> {
    let (req, cstate) = client::client_login_start(&ss(pwd)).unwrap();
    let (resp, sstate) =
        server::server_login_start(setup, record, &req, cid, handler, server_id, None)?;
    let (finalization, export_key) = client::client_login_finish(
        cstate,
        &resp,
        &ss(pwd),
        handler,
        server_id,
        None,
        Argon2Params::default(),
    )?;
    server::server_login_finish(&sstate, &finalization, handler, server_id, None)?;
    Ok(export_key)
}

#[test]
fn full_roundtrip_and_export_key_is_stable() {
    let setup = ServerSetup::generate();
    let (record, reg_key) = register(&setup, CID, PWD);

    let a = login(&setup, &record, CID, PWD, HANDLER, SERVER).unwrap();
    let b = login(&setup, &record, CID, PWD, HANDLER, SERVER).unwrap();
    assert_eq!(
        reg_key.expose_as_slice(),
        a.expose_as_slice(),
        "login must recover the export key"
    );
    assert_eq!(
        a.expose_as_slice(),
        b.expose_as_slice(),
        "export key is stable across logins"
    );
}

#[test]
fn setup_serialize_roundtrip_preserves_login() {
    let setup = ServerSetup::generate();
    let (record, reg_key) = register(&setup, CID, PWD);

    let setup2 = ServerSetup::deserialize(&setup.serialize()).unwrap();
    let key = login(&setup2, &record, CID, PWD, HANDLER, SERVER).unwrap();
    assert_eq!(reg_key.expose_as_slice(), key.expose_as_slice());
}

#[test]
fn different_passwords_yield_different_export_keys() {
    let setup = ServerSetup::generate();
    let (_, k1) = register(&setup, CID, PWD);
    let (_, k2) = register(&setup, CID, "Another-Pass-2!");
    assert_ne!(k1.expose_as_slice(), k2.expose_as_slice());
}

#[test]
fn wrong_password_login_fails() {
    let setup = ServerSetup::generate();
    let (record, _) = register(&setup, CID, PWD);
    assert!(login(&setup, &record, CID, "Wrong-Pass-9!", HANDLER, SERVER).is_err());
}

#[test]
fn wrong_identifiers_login_fails() {
    let setup = ServerSetup::generate();
    let (record, _) = register(&setup, CID, PWD);

    assert!(
        login(&setup, &record, CID, PWD, b"other-handle", SERVER).is_err(),
        "a different client identifier must not authenticate"
    );
    assert!(
        login(&setup, &record, CID, PWD, HANDLER, b"other.server").is_err(),
        "a different server identifier must not authenticate"
    );
}

#[test]
fn wrong_credential_identifier_login_fails() {
    let setup = ServerSetup::generate();
    let (record, _) = register(&setup, CID, PWD);
    assert!(login(&setup, &record, b"other-user", PWD, HANDLER, SERVER).is_err());
}

#[test]
fn record_from_another_setup_fails() {
    let setup_a = ServerSetup::generate();
    let setup_b = ServerSetup::generate();
    let (record, _) = register(&setup_a, CID, PWD);
    assert!(
        login(&setup_b, &record, CID, PWD, HANDLER, SERVER).is_err(),
        "a record is bound to the server setup it was made under"
    );
}

#[test]
fn tampered_record_does_not_authenticate() {
    let setup = ServerSetup::generate();
    let (record, _) = register(&setup, CID, PWD);

    let mut bad = record.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(login(&setup, &bad, CID, PWD, HANDLER, SERVER).is_err());
}

#[test]
fn malformed_server_setup_is_malformed_input() {
    let err = ServerSetup::deserialize(b"not a serialized setup")
        .err()
        .expect("deserialize of garbage must fail");
    assert!(is_malformed(err.kind), "got {:?}", err.kind);
}

#[test]
fn malformed_login_record_is_malformed_input_not_internal() {
    let setup = ServerSetup::generate();
    let err = server::server_login_start(
        &setup,
        b"corrupt-record",
        b"corrupt-request",
        CID,
        HANDLER,
        SERVER,
        None,
    )
    .unwrap_err();
    assert!(
        is_malformed(err.kind),
        "a corrupt stored record must not be an internal library bug: {:?}",
        err.kind
    );
}

#[test]
fn malformed_login_state_is_malformed_input_not_internal() {
    let err =
        server::server_login_finish(b"corrupt-state", b"corrupt-final", HANDLER, SERVER, None)
            .unwrap_err();
    assert!(
        is_malformed(err.kind),
        "a corrupt login state must not be an internal library bug: {:?}",
        err.kind
    );
}

#[test]
fn malformed_client_wire_messages_are_invalid_credentials() {
    let setup = ServerSetup::generate();

    let (_, cstate) = client::client_registration_start(&ss(PWD)).unwrap();
    let e = client::client_registration_finish(
        cstate,
        b"garbage",
        &ss(PWD),
        HANDLER,
        SERVER,
        Argon2Params::default(),
    )
    .unwrap_err();
    assert!(is_invalid_credentials(e.kind), "got {:?}", e.kind);

    let e = server::server_registration_finish(b"garbage-upload").unwrap_err();
    assert!(is_invalid_credentials(e.kind), "got {:?}", e.kind);

    let (_, cstate) = client::client_login_start(&ss(PWD)).unwrap();
    let e = client::client_login_finish(
        cstate,
        b"garbage",
        &ss(PWD),
        HANDLER,
        SERVER,
        None,
        Argon2Params::default(),
    )
    .unwrap_err();
    assert!(is_invalid_credentials(e.kind), "got {:?}", e.kind);

    let (record, _) = register(&setup, CID, PWD);
    let (req, _) = client::client_login_start(&ss(PWD)).unwrap();
    let (_, sstate) =
        server::server_login_start(&setup, &record, &req, CID, HANDLER, SERVER, None).unwrap();
    let e =
        server::server_login_finish(&sstate, b"garbage-final", HANDLER, SERVER, None).unwrap_err();
    assert!(is_invalid_credentials(e.kind), "got {:?}", e.kind);
}
