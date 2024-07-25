#![no_std]
#![no_main]

use caliptra_drivers::{Aes128, Aes192, Aes256, AesPeripherals, AesMode, AesOp};
use caliptra_test_harness::test_suite;

const SEED: [u8; 32] = [
    0x11, 0x11, 0x00, 0x00, 0x22, 0x22, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x44, 0x44, 0x00, 0x00,
    0x55, 0x55, 0x00, 0x00, 0x66, 0x66, 0x00, 0x00, 0x77, 0x77, 0x00, 0x00, 0x88, 0x88, 0x00, 0x00,
];

fn test_aes128() {
    let peripherals = unsafe { AesPeripherals::steal() };
    let mut output = [0; 32];

    let key = [
        0x77, 0x23, 0xd8, 0x7d, 0x77, 0x3a, 0x8b, 0xbf, 0xe1, 0xae, 0x5b, 0x08, 0x12, 0x35, 0xb5,
        0x66,
    ];
    let pt = [
        0x1b, 0x0a, 0x69, 0xb7, 0xbc, 0x53, 0x4c, 0x16, 0xce, 0xcf, 0xfa, 0xe0, 0x2c, 0xc5, 0x32,
        0x31, 0x90, 0xce, 0xb4, 0x13, 0xf1, 0xdb, 0x3e, 0x9f, 0x0f, 0x79, 0xba, 0x65, 0x4c, 0x54,
        0xb6, 0x0e,
    ];
    let ct = [
        0xad, 0x5b, 0x08, 0x95, 0x15, 0xe7, 0x82, 0x10, 0x87, 0xc6, 0x16, 0x52, 0xdc, 0x47, 0x7a,
        0xb1, 0xf2, 0xcc, 0x63, 0x31, 0xa7, 0x0d, 0xfc, 0x59, 0xc9, 0xff, 0xb0, 0xc7, 0x23, 0xc6,
        0x82, 0xf6,
    ];

    let mut aes = Aes128::new(
        peripherals.forti_crypt,
        AesOp::Enc,
        AesMode::ECB,
        Some(&key),
        None,
        SEED,
    )
    .unwrap();
    aes.run_core_b2b(&pt, &mut output, None).unwrap();
    assert_eq!(output, ct);
}

test_suite! {
    test_aes128,
}
