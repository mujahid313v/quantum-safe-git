use super::*;
use std::path::PathBuf;

const VECTOR_PASSPHRASE: &[u8] = b"qsgit fixed test vector passphrase";

fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("chmod temp directory");
    }
    dir
}

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/argon2id-test.qsgkey")
}

#[test]
fn encrypted_and_unencrypted_round_trip_and_signature() {
    let dir = private_tempdir();
    let passphrase = Passphrase::new("a test passphrase").unwrap();
    let info = generate(
        dir.path(),
        "encrypted",
        Some(&passphrase),
        "test key",
        false,
        false,
    )
    .unwrap();
    let (public, secret, kind) = load_secret(&info.private_path, Some(&passphrase), false).unwrap();
    assert_eq!(kind, KeyKind::Encrypted);
    let record = qsg_sshsig::sign_ml_dsa65(&public, &secret, b"keystore integration").unwrap();
    qsg_sshsig::verify_ml_dsa65(&record, b"keystore integration").unwrap();
    assert!(qsg_sshsig::verify_ml_dsa65(&record, b"tampered").is_err());

    let public_info = read_public(&info.public_path).unwrap();
    assert_eq!(public_info.comment, "test key");
    assert_eq!(public_info.fingerprint, info.fingerprint);
    assert_eq!(
        public_info.fingerprint,
        qsg_sshsig::fingerprint(&public_info.blob).unwrap()
    );
    let from_pub = load_secret(&info.public_path, Some(&passphrase), false).unwrap();
    assert_eq!(from_pub.2, KeyKind::Encrypted);
    let from_private = load_secret(&info.private_path, Some(&passphrase), false).unwrap();
    assert_eq!(from_private.2, KeyKind::Encrypted);

    let unencrypted = generate(dir.path(), "plain", None, "", false, true).unwrap();
    assert!(matches!(
        fs::read_to_string(&unencrypted.public_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .count(),
        2
    ));
    assert!(matches!(
        load_secret(&unencrypted.private_path, None, false),
        Err(Error::UnencryptedNotAllowed)
    ));
    let (_, _, kind) = load_secret(&unencrypted.private_path, None, true).unwrap();
    assert_eq!(kind, KeyKind::Unencrypted);
}

#[test]
fn wrong_passphrase_and_existing_key_are_rejected() {
    let dir = private_tempdir();
    let passphrase = Passphrase::new("right").unwrap();
    let info = generate(dir.path(), "key", Some(&passphrase), "", false, false).unwrap();
    let wrong = Passphrase::new("wrong").unwrap();
    assert!(matches!(
        load_secret(&info.private_path, Some(&wrong), false),
        Err(Error::WrongPassphraseOrCorrupt)
    ));
    assert!(matches!(
        generate(dir.path(), "key", Some(&passphrase), "", false, false),
        Err(Error::AlreadyExists)
    ));
    let replaced = generate(
        dir.path(),
        "key",
        Some(&passphrase),
        "replacement",
        true,
        false,
    )
    .unwrap();
    assert_eq!(
        read_public(&replaced.public_path).unwrap().comment,
        "replacement"
    );
    load_secret(&replaced.private_path, Some(&passphrase), false).unwrap();
}

#[test]
fn test_vector_is_stable_and_every_byte_mutation_fails_cleanly() {
    let bytes = fs::read(vector_path()).expect("fixed test vector exists");
    assert_eq!(bytes.len(), FILE_LEN);
    let passphrase = Passphrase::new(VECTOR_PASSPHRASE).unwrap();
    let (seed, kind) = decode_container(&bytes, Some(&passphrase), false, Bounds::test()).unwrap();
    assert_eq!(kind, KeyKind::Encrypted);
    assert_eq!(seed.len(), SEED_LEN);
    for index in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 1;
        let result = std::panic::catch_unwind(|| {
            decode_container(&corrupted, Some(&passphrase), true, Bounds::test())
        });
        assert!(result.is_ok(), "mutation at offset {index} panicked");
        assert!(
            result.unwrap().is_err(),
            "mutation at offset {index} unexpectedly parsed"
        );
    }
    for end in [0, 5, 58, FILE_LEN - 1] {
        assert!(decode_container(&bytes[..end], Some(&passphrase), false, Bounds::test()).is_err());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(matches!(
        decode_container(&extended, Some(&passphrase), false, Bounds::test()),
        Err(Error::InvalidLength)
    ));
}

#[test]
fn unknown_ids_and_argon_bounds_are_clear_errors() {
    let passphrase = Passphrase::new(VECTOR_PASSPHRASE).unwrap();
    let vector = fs::read(vector_path()).unwrap();
    for (offset, value, matches_error) in [
        (6, 99, 0),
        (7, 99, 1),
        (8, 99, 2),
        (34, 99, 3),
        (12, 7, 4),
        (16, 0, 4),
        (17, 0, 4),
    ] {
        let mut altered = vector.clone();
        altered[offset] = value;
        let result = decode_container(&altered, Some(&passphrase), false, Bounds::test());
        assert!(
            result.is_err(),
            "mutated header at offset {offset} was accepted"
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => unreachable!("checked above"),
        };
        match (matches_error, error) {
            (0, Error::UnsupportedVersion(_))
            | (1, Error::UnknownAlgorithm(_))
            | (2, Error::UnknownKdf(_))
            | (3, Error::UnknownAead(_))
            | (4, Error::KdfBounds) => {}
            (_, other) => panic!("unexpected validation error: {other}"),
        }
    }
    assert!(matches!(
        check_params(19_455, 2, 1, Bounds::production()),
        Err(Error::KdfBounds)
    ));
    assert!(matches!(
        check_params(131_073, 2, 1, Bounds::production()),
        Err(Error::KdfBounds)
    ));
    assert!(matches!(
        check_params(19_456, 7, 1, Bounds::production()),
        Err(Error::KdfBounds)
    ));
    assert!(matches!(
        check_params(19_456, 2, 5, Bounds::production()),
        Err(Error::KdfBounds)
    ));
}

#[test]
fn random_bytes_never_panic_in_container_decoder() {
    use proptest::prelude::*;
    proptest!(|(bytes in proptest::collection::vec(any::<u8>(), 0..300))| {
        let passphrase = Passphrase::new(VECTOR_PASSPHRASE).unwrap();
        let result = std::panic::catch_unwind(|| decode_container(&bytes, Some(&passphrase), true, Bounds::production()));
        prop_assert!(result.is_ok());
    });
}

#[cfg(unix)]
#[test]
fn unix_directory_and_private_file_permissions_are_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("keys")).unwrap();
    let keydir = dir.path().join("keys");
    fs::set_permissions(&keydir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        generate(&keydir, "key", None, "", false, true),
        Err(Error::Permissions { mode: "700", .. })
    ));
    fs::set_permissions(&keydir, fs::Permissions::from_mode(0o700)).unwrap();
    let info = generate(&keydir, "key", None, "", false, true).unwrap();
    assert_eq!(
        fs::metadata(&info.private_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::set_permissions(&info.private_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        load_secret(&info.private_path, None, true),
        Err(Error::Permissions { mode: "600", .. })
    ));
}

#[cfg(unix)]
#[test]
fn newly_created_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    let new_dir = parent.path().join("config/qsgit");
    generate(&new_dir, "key", None, "", false, true).unwrap();
    assert_eq!(
        fs::metadata(new_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn private_path_symlink_is_refused() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let target = dir.path().join("target");
        fs::write(&target, b"not a key").unwrap();
        let link = dir.path().join("link");
        symlink(target, &link).unwrap();
        assert!(matches!(
            load_secret(&link, None, true),
            Err(Error::Symlink)
        ));
        assert!(matches!(
            generate(dir.path(), "link", None, "", false, true),
            Err(Error::Symlink)
        ));
    }
}

#[test]
#[ignore = "run once when regenerating the deterministic cheap-Argon2 test vector"]
fn write_test_vector() {
    let mut seed = [0x42u8; SEED_LEN];
    let passphrase = Passphrase::new(VECTOR_PASSPHRASE).unwrap();
    let mut encoded = encode_container(&seed, Some(&passphrase), Some((8, 1, 1))).unwrap();
    // Stable nonces and salt are used only for the published, non-secret test fixture.
    encoded[18..34].copy_from_slice(&[0x11; SALT_LEN]);
    encoded[35..59].copy_from_slice(&[0x22; NONCE_LEN]);
    // Re-encode with the fixed salt and nonce after constructing its associated-data header.
    let mut header = encoded[..HEADER_LEN].to_vec();
    let key = derive_key(Some(&passphrase), KDF_ARGON2ID, 8, 1, 1, &header[18..34]).unwrap();
    let cipher_key = Key::try_from(&key[..]).unwrap();
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let nonce = XNonce::try_from(&header[35..59]).unwrap();
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &seed,
                aad: &header,
            },
        )
        .unwrap();
    header.extend_from_slice(&encrypted);
    fs::create_dir_all(vector_path().parent().unwrap()).unwrap();
    fs::write(vector_path(), header).unwrap();
    seed.zeroize();
}
