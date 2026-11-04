use age::secrecy::ExposeSecret;
use enstow::crypto::{decrypt_age, encrypt_file_age};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_encrypt_file_with_explicit_recipient() {
    let dir = tempdir().unwrap();
    let plaintext_file = dir.path().join("plain.env");
    let encrypted_file = dir.path().join("plain.env.age");
    let content = b"SECRET_API_TOKEN=xyz123\n";
    fs::write(&plaintext_file, content).unwrap();

    // Generate identity and recipient
    let key = age::x25519::Identity::generate();
    let pubkey_str = key.to_public().to_string();

    let key_file = dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Encrypt file using public recipient string
    encrypt_file_age(&plaintext_file, &encrypted_file, &[pubkey_str], None, false).unwrap();

    assert!(encrypted_file.exists());
    // Decrypt and verify payload
    let decrypted = decrypt_age(&encrypted_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_using_key_file() {
    let dir = tempdir().unwrap();
    let plaintext_file = dir.path().join("credentials.json");
    let encrypted_file = dir.path().join("credentials.json.age");
    let content = b"{\"key\": \"val\"}\n";
    fs::write(&plaintext_file, content).unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Encrypt file resolving recipient from identity key file
    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[],
        Some(&key_file),
        false,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, content);
}

const TEST_ED25519_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBJGoWXLvLl4ramBb22t/Cjjb9CflCYaSn0jKfDHiyKYwAAAJC6oXeRuqF3
kQAAAAtzc2gtZWQyNTUxOQAAACBJGoWXLvLl4ramBb22t/Cjjb9CflCYaSn0jKfDHiyKYw
AAAEB3bYZEpsXO0UVsS8EmNjABxHEO+pZR/bftJfkx5vF5WEkahZcu8uXitqYFvba38KON
v0J+UJhpKfSMp8MeLIpjAAAAC3Rlc3RAZW5zdG93AQI=
-----END OPENSSH PRIVATE KEY-----
";

const TEST_ED25519_PUB: &str = "\
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEkahZcu8uXitqYFvba38KONv0J+UJhpKfSMp8MeLIpj test@enstow
";

const TEST_RSA_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA2SM8wU5Viwgp2WODW0unTM8OseUgIzAMeeoFF/tWbihGv11CVoAR
fwbxF/JqYa99kvMZ4MsnZqkxchYDmKuCIWWqxH8kewBcBSRzWvIjUYtMjSFN+c6ja5gvZP
Pi8XrG1e7nGC3n7BT3v/0J00NdZ9vypN7+seN6jbikl8vy9RJXBTfU47PR32vT697vDNsU
R+qwuCmQVcYs6xfPZJ9vf492S32PhQQ8dixVaSa0HRCVuATzc54WX4i3nzA7xXx9sW0+QJ
/5k56/8dsCTZ/+7SKoPox1QFg8Zc3ZhSkqfnAWdBaprFlULbFJSRjVxlJG2e/xBPF22FoM
LAOGv6OQVQAAA8gFY9hUBWPYVAAAAAdzc2gtcnNhAAABAQDZIzzBTlWLCCnZY4NbS6dMzw
6x5SAjMAx56gUX+1ZuKEa/XUJWgBF/BvEX8mphr32S8xngyydmqTFyFgOYq4IhZarEfyR7
AFwFJHNa8iNRi0yNIU35zqNrmC9k8+LxesbV7ucYLefsFPe//QnTQ11n2/Kk3v6x43qNuK
SXy/L1ElcFN9Tjs9Hfa9Pr3u8M2xRH6rC4KZBVxizrF89kn29/j3ZLfY+FBDx2LFVpJrQd
EJW4BPNznhZfiLefMDvFfH2xbT5An/mTnr/x2wJNn/7tIqg+jHVAWDxlzdmFKSp+cBZ0Fq
msWVQtsUlJGNXGUkbZ7/EE8XbYWgwsA4a/o5BVAAAAAwEAAQAAAQAsW3Jx2trGyCgkbJvM
7quCmVnbJX9nMM2bqh7YQ1PotPme5iJDIW5xkK13wuHQitUQS/EhZt7pre6X679YVNEEmY
xFD+QX7H7f3g5iqcxlQBunSQJw4bGorTIhYWEfC4HK+j7jRZ13MOFbqwlyyvQt31S2MYe+
N0Y15V5aVCORxIjGj3ltiloatjT/1bFLJuB7Dcbx8YtY9KZvPN1JBnE2rCCmDA9fWW8U0t
y82fBfzCmzNwUGzYiTzBCnyhCvDxIUhpwf05wlMHlaCwwWNn1ntnxOT5DYtRLNVWvVr0lO
JJXPuEsZ2ZDjWjqXQE5smTQOFdWHrmOqXBrYH+fAqcERAAAAgQCjlIMVfYjAu9MmJiqgf2
twaX2GrsTQA8eFFkpdV/LY2VKrDFGrD7PP8An+6L6Re6SAQ2cYRsdgzocvQTq87+CX5uZk
l9IRaNF7zZ5orOPoWAuqneBLQJqU89ls1MWpqQd5G38XgK6ewK9+hCaDJMJSpFyQruriGp
dDBnESvYDlfgAAAIEA/Vknr+BAtTZ2wihWFVczOwhUZvMiYWs8tXendD/1x1186PQorVqx
1oOzfkLuG3obY3XeUIIrKeFbojVMMhOjRjVLJnUY5Ta8EoDoQaxslThEKl0JE76bb59l2q
Q8KcXPdJ9T+77btMKv61IcnItx4vG9OeBcEW/NyrjLyW1Inx8AAACBANtpDmK39jdo7qZq
EgujmgL5GZO8whdjFGCo/ibd6wKEynA8Fr/VjzwkdPx66rWrDhotVTZMMHgOHHo5upK8o0
WkgTrHepzgM2YIAFOJNhjlDsEY5E4mh2v5Q/K7/+oNzBPKPdhWMBby3LFiFlmRAeD51JFn
+DqjXsy6OJVO9gYLAAAAC3Rlc3RAZW5zdG93AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
";

const TEST_RSA_PUB: &str = "\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZIzzBTlWLCCnZY4NbS6dMzw6x5SAjMAx56gUX+1ZuKEa/XUJWgBF/BvEX8mphr32S8xngyydmqTFyFgOYq4IhZarEfyR7AFwFJHNa8iNRi0yNIU35zqNrmC9k8+LxesbV7ucYLefsFPe//QnTQ11n2/Kk3v6x43qNuKSXy/L1ElcFN9Tjs9Hfa9Pr3u8M2xRH6rC4KZBVxizrF89kn29/j3ZLfY+FBDx2LFVpJrQdEJW4BPNznhZfiLefMDvFfH2xbT5An/mTnr/x2wJNn/7tIqg+jHVAWDxlzdmFKSp+cBZ0FqmsWVQtsUlJGNXGUkbZ7/EE8XbYWgwsA4a/o5BV test@enstow
";

fn generate_ssh_key(
    dir: &std::path::Path,
    key_type: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let (priv_content, pub_content) = match key_type {
        "ed25519" => (TEST_ED25519_PRIV, TEST_ED25519_PUB),
        "rsa" => (TEST_RSA_PRIV, TEST_RSA_PUB),
        _ => panic!("unsupported key type"),
    };
    let priv_path = dir.join(format!("id_{key_type}"));
    let pub_path = dir.join(format!("id_{key_type}.pub"));
    fs::write(&priv_path, priv_content).unwrap();
    fs::write(&pub_path, pub_content).unwrap();
    (priv_path, pub_path)
}

#[test]
fn test_encrypt_file_with_ssh_ed25519_recipient() {
    let dir = tempdir().unwrap();
    let (priv_key, pub_key) = generate_ssh_key(dir.path(), "ed25519");
    let pubkey_str = fs::read_to_string(&pub_key).unwrap();

    let plaintext_file = dir.path().join("ssh_secret.env");
    let encrypted_file = dir.path().join("ssh_secret.env.age");
    let content = b"SSH_SUPER_SECRET=value123\n";
    fs::write(&plaintext_file, content).unwrap();

    // Encrypt using SSH ed25519 public recipient string
    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[pubkey_str.trim().to_string()],
        None,
        false,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_with_ssh_ed25519_pub_file() {
    let dir = tempdir().unwrap();
    let (priv_key, pub_key) = generate_ssh_key(dir.path(), "ed25519");

    let plaintext_file = dir.path().join("file_secret.env");
    let encrypted_file = dir.path().join("file_secret.env.age");
    let content = b"SECRET_FROM_FILE=abc\n";
    fs::write(&plaintext_file, content).unwrap();

    // Encrypt passing the path to the .pub file as recipient
    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[pub_key.to_string_lossy().to_string()],
        None,
        false,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_using_ssh_key_file() {
    let dir = tempdir().unwrap();
    let (priv_key, _pub_key) = generate_ssh_key(dir.path(), "ed25519");

    let plaintext_file = dir.path().join("auto_secret.txt");
    let encrypted_file = dir.path().join("auto_secret.txt.age");
    let content = b"auto-extracted ssh recipient\n";
    fs::write(&plaintext_file, content).unwrap();

    // Encrypt resolving recipient from SSH private key file
    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[],
        Some(&priv_key),
        false,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_with_ssh_rsa_recipient() {
    let dir = tempdir().unwrap();
    let (priv_key, pub_key) = generate_ssh_key(dir.path(), "rsa");
    let pubkey_str = fs::read_to_string(&pub_key).unwrap();

    let plaintext_file = dir.path().join("rsa_secret.txt");
    let encrypted_file = dir.path().join("rsa_secret.txt.age");
    let content = b"RSA_ENCRYPTED_SECRET\n";
    fs::write(&plaintext_file, content).unwrap();

    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[pubkey_str.trim().to_string()],
        None,
        false,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_with_passphrase_roundtrip() {
    let dir = tempdir().unwrap();
    let plaintext_file = dir.path().join("passphrase_plain.env");
    let encrypted_file = dir.path().join("passphrase_plain.env.age");
    let content = b"PASSPHRASE_SECRET_TOKEN=xyz789\n";
    fs::write(&plaintext_file, content).unwrap();

    std::env::set_var("ENSTOW_PASSPHRASE", "my-secret-passphrase-123");

    encrypt_file_age(&plaintext_file, &encrypted_file, &[], None, true).unwrap();

    assert!(encrypted_file.exists());

    let file = fs::File::open(&encrypted_file).unwrap();
    let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(file)).unwrap();
    assert!(decryptor.is_scrypt());

    // Decrypt without any key files
    let decrypted = decrypt_age(&encrypted_file, None).unwrap();
    assert_eq!(decrypted, content);

    // Decrypt with wrong passphrase should fail
    std::env::set_var("ENSTOW_PASSPHRASE", "wrong-password");
    let err = decrypt_age(&encrypted_file, None).unwrap_err();
    assert!(matches!(err, enstow::error::EnstowError::Decryption { .. }));

    std::env::remove_var("ENSTOW_PASSPHRASE");
}
