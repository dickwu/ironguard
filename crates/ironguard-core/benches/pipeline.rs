use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_buffer_pool_alloc_free(c: &mut Criterion) {
    use ironguard_core::pipeline::pool::BufferPool;
    let pool = BufferPool::new();
    c.bench_function("buffer_pool_alloc_free", |b| {
        b.iter(|| {
            let guard = pool.alloc_small().unwrap();
            black_box(guard.pool_idx());
        });
    });
}

fn bench_aes_gcm_seal_1500(c: &mut Criterion) {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let key_bytes = [0x42u8; 32];
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound);
    let nonce_bytes = [0u8; 12];

    c.bench_function("aes_256_gcm_seal_1500", |b| {
        let mut buf = vec![0u8; 1500];
        b.iter(|| {
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf)
                .unwrap();
            let _ = black_box(tag);
        });
    });
}

fn bench_aes_gcm_open_1500(c: &mut Criterion) {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let key_bytes = [0x42u8; 32];

    // Seal first to get valid ciphertext
    let seal_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());
    let mut buf = vec![0u8; 1500 + 16]; // payload + tag space
    buf[..1500].fill(0xAA);
    let nonce_bytes = [0u8; 12];
    let tag = seal_key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut buf[..1500],
        )
        .unwrap();
    buf[1500..].copy_from_slice(tag.as_ref());

    let open_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());

    c.bench_function("aes_256_gcm_open_1500", |b| {
        b.iter(|| {
            let mut test_buf = buf.clone();
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let result = open_key.open_in_place(nonce, Aad::empty(), &mut test_buf);
            let _ = black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_buffer_pool_alloc_free,
    bench_aes_gcm_seal_1500,
    bench_aes_gcm_open_1500
);
criterion_main!(benches);
