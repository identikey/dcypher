use criterion::{Criterion, black_box, criterion_group, criterion_main};
use recrypt_core::pre::backends::MockBackend;
use recrypt_core::*;

fn bench_encrypt(c: &mut Criterion) {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let data = vec![0u8; 1024]; // 1 KB

    c.bench_function("hybrid_encrypt_1kb", |b| {
        b.iter(|| encryptor.encrypt(black_box(&kp.public), black_box(&data)))
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let data = vec![0u8; 1024];
    let encrypted = encryptor.encrypt(&kp.public, &data).unwrap();

    c.bench_function("hybrid_decrypt_1kb", |b| {
        b.iter(|| encryptor.decrypt(black_box(&kp.secret), black_box(&encrypted)))
    });
}

fn bench_recrypt(c: &mut Criterion) {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let alice = encryptor.backend().generate_keypair().unwrap();
    let bob = encryptor.backend().generate_keypair().unwrap();
    let data = vec![0u8; 1024];
    let encrypted = encryptor.encrypt(&alice.public, &data).unwrap();
    let rk = encryptor
        .backend()
        .generate_recrypt_key(&alice.secret, &bob.public)
        .unwrap();

    c.bench_function("hybrid_recrypt_1kb", |b| {
        b.iter(|| encryptor.recrypt(black_box(&rk), black_box(&encrypted)))
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_recrypt);
criterion_main!(benches);
