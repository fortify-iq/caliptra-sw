/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384.rs

Abstract:

    File contains API for ECC-384 Cryptography operations

--*/

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    array_concat3, okmutref, wait, Array4x12, Array4xN, CaliptraError, CaliptraResult, KeyReadArgs,
    KeyWriteArgs, Trng,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::ecc::EccReg;
use core::cmp::Ordering;
use pka_hal::{Peripherals, Pka};
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

/// ECC-384 Coordinate
pub type Ecc384Scalar = Array4x12;

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecc384Result {
    Success = 0xAAAAAAAA,
    SigVerifyFailed = 0x55555555,
}

/// ECC-384 Seed
#[derive(Debug, Copy, Clone)]
pub enum Ecc384Seed<'a> {
    /// Array
    Array4x12(&'a Ecc384Scalar),

    /// Key Vault Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x12> for Ecc384Seed<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl From<KeyReadArgs> for Ecc384Seed<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// ECC-384 Public Key output
#[derive(Debug)]
pub enum Ecc384PrivKeyOut<'a> {
    /// Array
    Array4x12(&'a mut Ecc384Scalar),

    /// Key Vault Key
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut Array4x12> for Ecc384PrivKeyOut<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<KeyWriteArgs> for Ecc384PrivKeyOut<'a> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

/// ECC-384 Public Key input
#[derive(Debug, Copy, Clone)]
pub enum Ecc384PrivKeyIn<'a> {
    /// Array
    Array4x12(&'a Ecc384Scalar),

    /// Key Vault Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x12> for Ecc384PrivKeyIn<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}
impl From<KeyReadArgs> for Ecc384PrivKeyIn<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}
impl<'a> From<Ecc384PrivKeyOut<'a>> for Ecc384PrivKeyIn<'a> {
    fn from(value: Ecc384PrivKeyOut<'a>) -> Self {
        match value {
            Ecc384PrivKeyOut::Array4x12(arr) => Ecc384PrivKeyIn::Array4x12(arr),
            Ecc384PrivKeyOut::Key(key) => Ecc384PrivKeyIn::Key(KeyReadArgs { id: key.id }),
        }
    }
}

/// ECC-384 Public Key
#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Default, Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct Ecc384PubKey {
    /// X coordinate
    pub x: Ecc384Scalar,

    /// Y coordinate
    pub y: Ecc384Scalar,
}

impl Ecc384PubKey {
    /// Return DER formatted public key in uncompressed form
    #[inline(never)]
    pub fn to_der(&self) -> [u8; 97] {
        array_concat3([0x04], (&self.x).into(), (&self.y).into())
    }
}

/// ECC-384 Signature
#[repr(C)]
#[derive(Debug, Default, AsBytes, FromBytes, Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct Ecc384Signature {
    /// Random point
    pub r: Ecc384Scalar,

    /// Proof
    pub s: Ecc384Scalar,
}

/// Elliptic Curve P-384 API
pub struct Ecc384 {
    ecc: EccReg,
    pka: Pka,
}

impl Ecc384 {
    const ECC_P: [u32; 12] = [
        0xffffffff,
        0x00000000,
        0x00000000,
        0xffffffff,
        0xfffffffe,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
    ];

    const ECC_N: [u32; 12]  = [
        0xccc52973,
        0xecec196a,
        0x48b0a77a,
        0x581a0db2,
        0xf4372ddf,
        0xc7634d81,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
    ];

    const ECC_A: [u32; 12]  = [
        0xfffffffc,
        0x00000000,
        0x00000000,
        0xffffffff,
        0xfffffffe,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
    ];

    const ECC_B: [u32; 12]  = [
        0xd3ec2aef,
        0x2a85c8ed,
        0x8a2ed19d,
        0xc656398d,
        0x5013875a,
        0x0314088f,
        0xfe814112,
        0x181d9c6e,
        0xe3f82d19,
        0x988e056b,
        0xe23ee7e4,
        0xb3312fa7,
    ];

    const ECC_GX: [u32; 12] = [
        0x72760ab7,
        0x3a545e38,
        0xbf55296c,
        0x5502f25d,
        0x82542a38,
        0x59f741e0,
        0x8ba79b98,
        0x6e1d3b62,
        0xf320ad74,
        0x8eb1c71e,
        0xbe8b0537,
        0xaa87ca22,
    ];

    const ECC_GY: [u32; 12] = [
        0x90ea0e5f,
        0x7a431d7c,
        0x1d7e819d,
        0x0a60b1ce,
        0xb5f0b8c0,
        0xe9da3113,
        0x289a147c,
        0xf8f41dbd,
        0x9292dc29,
        0x5d9e98bf,
        0x96262c6f,
        0x3617de4a,
    ];

    const ECC_GZ: [u32; 12] = [
        0x00000001,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
    ];

    const PKA_MOD_ADDR: u32 =      0x0000_0000;
    const PKA_X0_ADDR: u32 =       0x0000_0060;
    const PKA_Y0_ADDR: u32 =       0x0000_00C0;
    const PKA_Z0_ADDR: u32 =       0x0000_0120;
    const PKA_X1_ADDR: u32 =       0x0000_0180;
    const PKA_Y1_ADDR: u32 =       0x0000_01E0;
    const PKA_Z1_ADDR: u32 =       0x0000_0240;
    const PKA_RESX_ADDR: u32 =     0x0000_02A0;
    const PKA_RESY_ADDR: u32 =     0x0000_0300;
    const PKA_RESZ_ADDR: u32 =     0x0000_0360;
    const PKA_A_ADDR: u32 =        0x0000_03C0;
    const PKA_SCALAR_ADDR: u32 =   0x0000_0420;
    const PKA_B_ADDR: u32 =        0x0000_0480;
    const PKA_MINV_OP_ADDR: u32 =  0x0000_0200;
    const PKA_MINV_RES_ADDR: u32 = 0x0000_0400;
    const PKA_MMUL_OP1_ADDR: u32 = 0x0000_0200;
    const PKA_MMUL_OP2_ADDR: u32 = 0x0000_0400;
    const PKA_MMUL_RES_ADDR: u32 = 0x0000_0600;
    const PKA_MADD_OP1_ADDR: u32 = 0x0000_0200;
    const PKA_MADD_OP2_ADDR: u32 = 0x0000_0400;
    const PKA_MADD_RES_ADDR: u32 = 0x0000_0600;

    const PKA_NI_0_VAL: u32 =     0x0000_0000;
    const PKA_NI_1_VAL: u32 =     0x0000_0010;
    const PKA_ENTR_MM_VAL: u32 =  0x0000_0000;
    const PKA_ENTR_PA_VAL: u32 =  0x0000_0010;
    const PKA_ENTR_SM_VAL: u32 =  0x0000_0018;
    const PKA_ENTR_MI_VAL: u32 =  0x0000_0030;
    const PKA_ENTR_MA_VAL: u32 =  0x0000_0038;
    const PKA_CTRL_VAL: u32 =     0x0030_0001;


    pub fn new(ecc: EccReg) -> Self {
        Self {
            ecc,
            pka: Pka::new(unsafe { Peripherals::steal().PKA }),
        }
    }

    // Check that `scalar` is in the range [1, n-1] for the P-384 curve
    fn scalar_range_check(scalar: &Ecc384Scalar) -> bool {
        // n-1 for The NIST P-384 curve
        const SECP384_ORDER_MIN1: &[u32] = &[
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xc7634d81,
            0xf4372ddf, 0x581a0db2, 0x48b0a77a, 0xecec196a, 0xccc52972,
        ];

        // Check scalar <= n-1
        for (i, word) in SECP384_ORDER_MIN1.iter().enumerate() {
            match scalar.0[i].cmp(word) {
                Ordering::Greater => return false,
                Ordering::Less => break,
                Ordering::Equal => continue,
            }
        }

        // If scalar is non-zero, return true
        for word in scalar.0 {
            if word != 0 {
                return true;
            }
        }

        // scalar is zero
        false
    }

    /// Generate ECC-384 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed for deterministic ECC Key Pair generation
    /// * `nonce` - Nonce for deterministic ECC Key Pair generation
    /// * `trng` - TRNG driver instance
    /// * `priv_key` - Generate ECC-384 Private key
    ///
    /// # Returns
    ///
    /// * `Ecc384PubKey` - Generated ECC-384 Public Key
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn key_pair(
        &mut self,
        seed: &Ecc384Seed,
        nonce: &Array4x12,
        trng: &mut Trng,
        priv_key: Ecc384PrivKeyOut,
    ) -> CaliptraResult<Ecc384PubKey> {
        let ecc = self.ecc.regs_mut();
        let mut priv_key = priv_key;

        // Wait for hardware ready
        wait::until(|| ecc.status().read().ready());

        // Configure hardware to route keys to user specified hardware blocks
        match &mut priv_key {
            Ecc384PrivKeyOut::Array4x12(_arr) => {
                KvAccess::begin_copy_to_arr(ecc.kv_wr_pkey_status(), ecc.kv_wr_pkey_ctrl())?;
            }
            Ecc384PrivKeyOut::Key(key) => {
                if !key.usage.ecc_private_key() {
                    // The key MUST be usable as a private key so we can do a
                    // pairwise consistency test, which is required to prevent
                    // leakage of secret material if the peripheral is glitched.
                    return Err(CaliptraError::DRIVER_ECC384_KEYGEN_BAD_USAGE);
                }

                KvAccess::begin_copy_to_kv(ecc.kv_wr_pkey_status(), ecc.kv_wr_pkey_ctrl(), *key)?;
            }
        }

        // Copy seed to the hardware
        match seed {
            Ecc384Seed::Array4x12(arr) => KvAccess::copy_from_arr(arr, ecc.seed())?,
            Ecc384Seed::Key(key) => {
                KvAccess::copy_from_kv(*key, ecc.kv_rd_seed_status(), ecc.kv_rd_seed_ctrl())
                    .map_err(|err| err.into_read_seed_err())?
            }
        }

        // Copy nonce to the hardware
        KvAccess::copy_from_arr(nonce, ecc.nonce())?;

        // Generate an IV.
        let iv = trng.generate()?;
        KvAccess::copy_from_arr(&iv, ecc.iv())?;

        // Program the command register for key generation
        ecc.ctrl().write(|w| w.ctrl(|w| w.keygen()));

        // Wait for command to complete
        wait::until(|| ecc.status().read().valid());

        // Copy the private key
        match &mut priv_key {
            Ecc384PrivKeyOut::Array4x12(arr) => KvAccess::end_copy_to_arr(ecc.privkey_out(), arr)?,
            Ecc384PrivKeyOut::Key(key) => {
                KvAccess::end_copy_to_kv(ecc.kv_wr_pkey_status(), *key)
                    .map_err(|err| err.into_write_priv_key_err())?;
            }
        }

        // Read private key
        let mut le_priv_key = match &priv_key {
            Ecc384PrivKeyOut::Array4x12(arr) => {
                arr.0
            },
            Ecc384PrivKeyOut::Key(key) => {
                todo!();
            }
        };
        le_priv_key.reverse();

        // === Projective coordinates randomization ===============

        // Read lambda value to randomize projective coordinates
        let mut g_proj_z = ecc.lambda().read();
        g_proj_z.reverse();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(Ecc384::ECC_P.len(), &Ecc384::ECC_P, Ecc384::PKA_MOD_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_GX.len(), &Ecc384::ECC_GX, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.dmem_write(g_proj_z.len(), &g_proj_z, Ecc384::PKA_MMUL_OP2_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize G.X computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read G.X data
        let mut g_proj_x = [0; 12];
        self.pka.dmem_read(g_proj_x.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut g_proj_x).unwrap();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(Ecc384::ECC_GY.len(), &Ecc384::ECC_GY, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize G.Y computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read G.Y data
        let mut g_proj_y = [0; 12];
        self.pka.dmem_read(g_proj_y.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut g_proj_y).unwrap();

        // === Public key generation ==============================

        // Write to PKA modulus P, curve parameters A and B, and base point G(x, y, z)
        self.pka.dmem_write(Ecc384::ECC_A.len(), &Ecc384::ECC_A, Ecc384::PKA_A_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_B.len(), &Ecc384::ECC_B, Ecc384::PKA_B_ADDR).unwrap();
        self.pka.dmem_write(g_proj_x.len(), &g_proj_x, Ecc384::PKA_X0_ADDR).unwrap();
        self.pka.dmem_write(g_proj_y.len(), &g_proj_y, Ecc384::PKA_Y0_ADDR).unwrap();
        self.pka.dmem_write(g_proj_z.len(), &g_proj_z, Ecc384::PKA_Z0_ADDR).unwrap();
        self.pka.dmem_write(le_priv_key.len(), &le_priv_key, Ecc384::PKA_SCALAR_ADDR).unwrap();

        // Write to PKA approximation of 1/P and command "ScalarMult"
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_SM_VAL)});

        // Initialize (privkey x G) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (privkey x G) data
        let mut pub_key_proj_x = [0; 12];
        self.pka.dmem_read(pub_key_proj_x.len(), Ecc384::PKA_RESX_ADDR, &mut pub_key_proj_x).unwrap();
        let mut pub_key_proj_y = [0; 12];
        self.pka.dmem_read(pub_key_proj_y.len(), Ecc384::PKA_RESY_ADDR, &mut pub_key_proj_y).unwrap();
        let mut pub_key_proj_z = [0; 12];
        self.pka.dmem_read(pub_key_proj_z.len(), Ecc384::PKA_RESZ_ADDR, &mut pub_key_proj_z).unwrap();

        // Write to PKA approximation of 1/P and command "ModInv"
        self.pka.dmem_write(pub_key_proj_z.len(), &pub_key_proj_z, Ecc384::PKA_MINV_OP_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MI_VAL)});

        // Initialize (1 / G(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read zinv = (1 / G(z)) data
        let mut z_inv = [0; 12];
        self.pka.dmem_read(z_inv.len(), Ecc384::PKA_MINV_RES_ADDR, &mut z_inv).unwrap();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(pub_key_proj_x.len(), &pub_key_proj_x, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (G(x) / G(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (G(x) / G(z)) data
        let mut pub_key_x = [0; 12];
        self.pka.dmem_read(pub_key_x.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut pub_key_x).unwrap();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(pub_key_proj_y.len(), &pub_key_proj_y, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (G(y) / G(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (G(y) / G(z)) data
        let mut pub_key_y = [0; 12];
        self.pka.dmem_read(pub_key_y.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut pub_key_y).unwrap();

        pub_key_x.reverse();
        pub_key_y.reverse();

        let pub_key = Ecc384PubKey {
            x: Array4x12::new(pub_key_x),
            y: Array4x12::new(pub_key_y),
        };

        // Pairwise consistency check.
        let digest = Array4x12::new([0u32; 12]);
        match self.sign(&priv_key.into(), &pub_key, &digest, trng) {
            Ok(mut sig) => sig.zeroize(),
            Err(err) => return Err(err),
        }

        self.zeroize_internal();

        Ok(pub_key)
    }

    /// Sign the PCR digest with PCR signing private key.
    ///
    /// # Arguments
    ///
    /// * `trng` - TRNG driver instance
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Generate signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn pcr_sign_flow(&mut self, trng: &mut Trng) -> CaliptraResult<Ecc384Signature> {
        todo!()
        // let ecc = self.ecc.regs_mut();

        // // Wait for hardware ready
        // wait::until(|| ecc.status().read().ready());

        // // Generate an IV.
        // let iv = trng.generate()?;
        // KvAccess::copy_from_arr(&iv, ecc.iv())?;

        // ecc.ctrl().write(|w| w.pcr_sign(true).ctrl(|w| w.signing()));

        // // Wait for command to complete
        // wait::until(|| ecc.status().read().valid());

        // // Copy signature
        // let signature = Ecc384Signature {
        //     r: Array4x12::read_from_reg(ecc.sign_r()),
        //     s: Array4x12::read_from_reg(ecc.sign_s()),
        // };

        // self.zeroize_internal();

        // Ok(signature)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn sign_internal(
        &mut self,
        priv_key: &Ecc384PrivKeyIn,
        data: &Ecc384Scalar,
        trng: &mut Trng,
    ) -> CaliptraResult<Ecc384Signature> {
        // TODO: need to convert PkaError into CaliptraError somehow
        // TODO: maybe should not call `.len()` for args in `dmem_write` and `dmem_read` since it is always the same everywhere
        let ecc = self.ecc.regs_mut();

        // Wait for hardware ready
        wait::until(|| ecc.status().read().ready());

        // === Random number k generation =========================

        // Copy private key
        match priv_key {
            Ecc384PrivKeyIn::Array4x12(arr) => KvAccess::copy_from_arr(arr, ecc.privkey_in())?,
            Ecc384PrivKeyIn::Key(key) => {
                KvAccess::copy_from_kv(*key, ecc.kv_rd_pkey_status(), ecc.kv_rd_pkey_ctrl())
                    .map_err(|err| err.into_read_priv_key_err())?
            }
        }

        // Copy digest
        KvAccess::copy_from_arr(data, ecc.msg())?;

        // Generate an IV.
        let iv = trng.generate()?;
        KvAccess::copy_from_arr(&iv, ecc.iv())?;

        // Program the command register
        ecc.ctrl().write(|w| w.ctrl(|w| w.signing()));

        // Wait for command to complete
        wait::until(|| ecc.status().read().valid());

        // Read k value from PKA
        let mut k = ecc.privkey_out().read();
        k.reverse();

        // === Projective coordinates randomization ===============

        // Read lambda value to randomize projective coordinates
        let mut g_proj_z = ecc.lambda().read();
        g_proj_z.reverse();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(Ecc384::ECC_P.len(), &Ecc384::ECC_P, Ecc384::PKA_MOD_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_GX.len(), &Ecc384::ECC_GX, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.dmem_write(g_proj_z.len(), &g_proj_z, Ecc384::PKA_MMUL_OP2_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize G.X computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read G.X data
        let mut g_proj_x = [0; 12];
        self.pka.dmem_read(g_proj_x.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut g_proj_x).unwrap();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(Ecc384::ECC_GY.len(), &Ecc384::ECC_GY, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize G.Y computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read G.Y data
        let mut g_proj_y = [0; 12];
        self.pka.dmem_read(g_proj_y.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut g_proj_y).unwrap();

        // === Random point R calculation =========================

        // Write to PKA modulus P, curve parameters A and B, and base point G(x, y, z)
        self.pka.dmem_write(Ecc384::ECC_A.len(), &Ecc384::ECC_A, Ecc384::PKA_A_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_B.len(), &Ecc384::ECC_B, Ecc384::PKA_B_ADDR).unwrap();
        self.pka.dmem_write(g_proj_x.len(), &g_proj_x, Ecc384::PKA_X0_ADDR).unwrap();
        self.pka.dmem_write(g_proj_y.len(), &g_proj_y, Ecc384::PKA_Y0_ADDR).unwrap();
        self.pka.dmem_write(g_proj_z.len(), &g_proj_z, Ecc384::PKA_Z0_ADDR).unwrap();

        // Write to PKA approximation of 1/P and command "ScalarMult"
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_SM_VAL)});

        self.pka.dmem_write(k.len(), &k, Ecc384::PKA_SCALAR_ADDR).unwrap();

        // Initialize (k x G) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (k x G) data
        let mut r_proj_x = [0; 12];
        self.pka.dmem_read(r_proj_x.len(), Ecc384::PKA_RESX_ADDR, &mut r_proj_x).unwrap();
        let mut r_proj_y = [0; 12];
        self.pka.dmem_read(r_proj_y.len(), Ecc384::PKA_RESY_ADDR, &mut r_proj_y).unwrap();
        let mut r_proj_z = [0; 12];
        self.pka.dmem_read(r_proj_z.len(), Ecc384::PKA_RESZ_ADDR, &mut r_proj_z).unwrap();

        // Write to PKA approximation of 1/P and command "ModInv"
        self.pka.dmem_write(r_proj_z.len(), &r_proj_z, Ecc384::PKA_MINV_OP_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MI_VAL)});

        // Initialize (1 / G(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (1 / G(z)) data
        let mut z_inv = [0; 12];
        self.pka.dmem_read(z_inv.len(), Ecc384::PKA_MINV_RES_ADDR, &mut z_inv).unwrap();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(r_proj_x.len(), &r_proj_x, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (G(x) / G(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read R = (G(x) / G(z)) data
        let mut r = [0; 12];
        self.pka.dmem_read(r.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut r).unwrap();

        // === Signature proof S calculation ======================

        // Write to PKA modulus N
        self.pka.dmem_write(Ecc384::ECC_N.len(), &Ecc384::ECC_N, Ecc384::PKA_MOD_ADDR).unwrap();

        // Write to PKA R, privkey and command "ModMult"
        self.pka.dmem_write(r.len(), &r, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        let mut le_priv_key = match priv_key {
            Ecc384PrivKeyIn::Array4x12(arr) => {
                arr.0
            },
            Ecc384PrivKeyIn::Key(key) => {
                todo!();
            }
        };
        le_priv_key.reverse();

        self.pka.dmem_write(le_priv_key.len(), &le_priv_key, Ecc384::PKA_MMUL_OP2_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (R * privkey) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (R * privkey) data
        let mut s = [0; 12];
        self.pka.dmem_read(s.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut s).unwrap();

        // Write to PKA (R * privkey), hashed message and command "ModAdd"
        self.pka.dmem_write(s.len(), &s, Ecc384::PKA_MADD_OP1_ADDR).unwrap();
        let mut le_data = data.0;
        le_data.reverse();
        self.pka.dmem_write(le_data.len(), &le_data, Ecc384::PKA_MADD_OP2_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MA_VAL)});

        // Initialize (h + R * privkey) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (h + R * privkey) data
        self.pka.dmem_read(s.len(), Ecc384::PKA_MADD_RES_ADDR, &mut s).unwrap();

        // Write to PKA approximation of 1/P and command "ModInv"
        self.pka.dmem_write(k.len(), &k, Ecc384::PKA_MINV_OP_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MI_VAL)});

        // Initialize (1 / K) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (1 / K) data
        self.pka.dmem_read(k.len(), Ecc384::PKA_MINV_RES_ADDR, &mut k).unwrap();

        // Write to PKA (1 / K), (h + R * privkey) and command "ModMult"
        self.pka.dmem_write(k.len(), &k, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.dmem_write(s.len(), &s, Ecc384::PKA_MMUL_OP2_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize S computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read S data
        self.pka.dmem_read(s.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut s).unwrap();

        r.reverse();
        s.reverse();

        // Copy signature
        let signature = Ecc384Signature {
            r: Array4x12::new(r),
            s: Array4x12::new(s),
        };

        self.zeroize_internal();

        Ok(signature)
    }

    /// Sign the digest with specified private key. To defend against glitching
    /// attacks that could expose the private key, this function also verifies
    /// the generated signature.
    ///
    /// # Arguments
    ///
    /// * `priv_key` - Private key
    /// * `pub_key` - Public key to verify with
    /// * `data` - Digest to sign
    /// * `trng` - TRNG driver instance
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Generate signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sign(
        &mut self,
        priv_key: &Ecc384PrivKeyIn,
        pub_key: &Ecc384PubKey,
        data: &Ecc384Scalar,
        trng: &mut Trng,
    ) -> CaliptraResult<Ecc384Signature> {
        let mut sig_result = self.sign_internal(priv_key, data, trng);
        let sig = okmutref(&mut sig_result)?;

        let r = self.verify_r(pub_key, data, sig)?;
        caliptra_cfi_lib::cfi_assert_eq_12_words(&r.0, &sig.r.0);
        sig_result
    }

    /// Verify signature with specified public key and digest
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `digest` - digest to verify
    /// * `signature` - Signature to verify
    ///
    ///  Note: Use this function only if glitch protection is not needed.
    ///        If glitch protection is needed, use `verify_r` instead.
    ///
    ///
    /// # Result
    ///
    /// *  `Ecc384Result` - Ecc384Result::Success if the signature verification passed else an error code.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn verify(
        &mut self,
        pub_key: &Ecc384PubKey,
        digest: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> CaliptraResult<Ecc384Result> {
        // Get the verify r result
        let mut verify_r = self.verify_r(pub_key, digest, signature)?;

        // compare the hardware generate `r` with one in signature
        let result = if verify_r == signature.r {
            caliptra_cfi_lib::cfi_assert_eq_12_words(&verify_r.0, &signature.r.0);
            Ecc384Result::Success
        } else {
            Ecc384Result::SigVerifyFailed
        };

        verify_r.0.zeroize();
        Ok(result)
    }

    /// Returns the R value of the signature with specified public key and digest.
    ///  Caller is expected to compare the returned R value against the provided signature's
    ///  R value to determine whether the signature is valid.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `digest` - digest to verify
    /// * `signature` - Signature to verify
    ///
    /// # Result
    ///
    /// *  `Array4xN<12, 48>` - verify R value
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn verify_r(
        &mut self,
        pub_key: &Ecc384PubKey,
        digest: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> CaliptraResult<Array4xN<12, 48>> {
        // If R or S are not in the range [1, N-1], signature check must fail
        if !Self::scalar_range_check(&signature.r) || !Self::scalar_range_check(&signature.s) {
            return Err(CaliptraError::DRIVER_ECC384_SCALAR_RANGE_CHECK_FAILED);
        }

        let ecc = self.ecc.regs_mut();

        // Wait for hardware ready
        wait::until(|| ecc.status().read().ready());

        // Program the command register
        ecc.ctrl().write(|w| w.ctrl(|w| w.verifying()));

        // Wait for command to complete
        wait::until(|| ecc.status().read().valid());

        let mut u1_gx = [0; 12];
        let mut u1_gy = [0; 12];
        let mut u1_gz = [0; 12];

        // Write to PKA modulus N, approximation of 1/N and command "ModInv"
        self.pka.dmem_write(Ecc384::ECC_N.len(), &Ecc384::ECC_N, Ecc384::PKA_MOD_ADDR).unwrap();
        let mut le_s = signature.s.0;
        le_s.reverse();
        self.pka.dmem_write(le_s.len(), &le_s, Ecc384::PKA_MINV_OP_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MI_VAL)});

        // Initialize (1 / S) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (1 / S) data
        let mut s_inv = [0; 12];
        self.pka.dmem_read(s_inv.len(), Ecc384::PKA_MINV_RES_ADDR, &mut s_inv).unwrap();

        // Write to PKA approximation of 1/N and command "ModMult"
        let mut le_digest = digest.0;
        le_digest.reverse();
        self.pka.dmem_write(le_digest.len(), &le_digest, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.dmem_write(s_inv.len(), &s_inv, Ecc384::PKA_MMUL_OP2_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (h * s1) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read u1 = (h * s1) data
        let mut u1 = [0; 12];
        self.pka.dmem_read(u1.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut u1).unwrap();

        // Write to PKA approximation of 1/N and command "ModMult"
        let mut le_r = signature.r.0;
        le_r.reverse();
        self.pka.dmem_write(le_r.len(), &le_r, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (r * s1) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read u2 = (r * s1) data
        let mut u2 = [0; 12];
        self.pka.dmem_read(u2.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut u2).unwrap();
        if u1.iter().any(|&x| x != 0) {
            // Write to PKA modulus P, curve parameters A and B, base point G(x, y, z) and scalar
            self.pka.dmem_write(Ecc384::ECC_P.len(), &Ecc384::ECC_P, Ecc384::PKA_MOD_ADDR).unwrap();
            self.pka.dmem_write(Ecc384::ECC_A.len(), &Ecc384::ECC_A, Ecc384::PKA_A_ADDR).unwrap();
            self.pka.dmem_write(Ecc384::ECC_B.len(), &Ecc384::ECC_B, Ecc384::PKA_B_ADDR).unwrap();
            self.pka.dmem_write(Ecc384::ECC_GX.len(), &Ecc384::ECC_GX, Ecc384::PKA_X0_ADDR).unwrap();
            self.pka.dmem_write(Ecc384::ECC_GY.len(), &Ecc384::ECC_GY, Ecc384::PKA_Y0_ADDR).unwrap();
            self.pka.dmem_write(Ecc384::ECC_GZ.len(), &Ecc384::ECC_GZ, Ecc384::PKA_Z0_ADDR).unwrap();
            self.pka.dmem_write(u1.len(), &u1, Ecc384::PKA_SCALAR_ADDR).unwrap();

            // Write to PKA approximation of 1/P and command "ScalarMult"
            self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
            self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
            self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_SM_VAL)});

            // Initialize (u1 x G) computation in PKA
            self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
            self.pka.wait_for_done().unwrap();

            // Read (u1 x G) data
            self.pka.dmem_read(u1_gx.len(), Ecc384::PKA_RESX_ADDR, &mut u1_gx).unwrap();
            self.pka.dmem_read(u1_gy.len(), Ecc384::PKA_RESY_ADDR, &mut u1_gy).unwrap();
            self.pka.dmem_read(u1_gz.len(), Ecc384::PKA_RESZ_ADDR, &mut u1_gz).unwrap();
        }

        // Write to PKA modulus P, curve parameters A and B, base point pubkey(x, y, z) and scalar
        self.pka.dmem_write(Ecc384::ECC_P.len(), &Ecc384::ECC_P, Ecc384::PKA_MOD_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_A.len(), &Ecc384::ECC_A, Ecc384::PKA_A_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_B.len(), &Ecc384::ECC_B, Ecc384::PKA_B_ADDR).unwrap();
        let mut le_pub_key_x = pub_key.x.0;
        le_pub_key_x.reverse();
        self.pka.dmem_write(le_pub_key_x.len(), &le_pub_key_x, Ecc384::PKA_X0_ADDR).unwrap();
        let mut le_pub_key_y = pub_key.y.0;
        le_pub_key_y.reverse();
        self.pka.dmem_write(le_pub_key_y.len(), &le_pub_key_y, Ecc384::PKA_Y0_ADDR).unwrap();
        self.pka.dmem_write(Ecc384::ECC_GZ.len(), &Ecc384::ECC_GZ, Ecc384::PKA_Z0_ADDR).unwrap();
        self.pka.dmem_write(u2.len(), &u2, Ecc384::PKA_SCALAR_ADDR).unwrap();

        // Write to PKA approximation of 1/P and command "ScalarMult"
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_SM_VAL)});

        // Initialize (u2 x pubkey) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (u2 x pubkey) data
        let mut u2_pub_key_x = [0; 12];
        self.pka.dmem_read(u2_pub_key_x.len(), Ecc384::PKA_RESX_ADDR, &mut u2_pub_key_x).unwrap();
        let mut u2_pub_key_y = [0; 12];
        self.pka.dmem_read(u2_pub_key_y.len(), Ecc384::PKA_RESY_ADDR, &mut u2_pub_key_y).unwrap();
        let mut u2_pub_key_z = [0; 12];
        self.pka.dmem_read(u2_pub_key_z.len(), Ecc384::PKA_RESZ_ADDR, &mut u2_pub_key_z).unwrap();

        let mut r_proj_x = [0; 12];
        let mut r_proj_z = [0; 12];
        if u1.iter().any(|&x| x != 0) {
            // Write to PKA modulus P, and points (u1 x G) and (u2 x pubkey)
            self.pka.dmem_write(Ecc384::ECC_P.len(), &Ecc384::ECC_P, Ecc384::PKA_MOD_ADDR).unwrap();
            self.pka.dmem_write(u1_gx.len(), &u1_gx, Ecc384::PKA_X0_ADDR).unwrap();
            self.pka.dmem_write(u1_gy.len(), &u1_gy, Ecc384::PKA_Y0_ADDR).unwrap();
            self.pka.dmem_write(u1_gz.len(), &u1_gz, Ecc384::PKA_Z0_ADDR).unwrap();
            self.pka.dmem_write(u2_pub_key_x.len(), &u2_pub_key_x, Ecc384::PKA_X1_ADDR).unwrap();
            self.pka.dmem_write(u2_pub_key_y.len(), &u2_pub_key_y, Ecc384::PKA_Y1_ADDR).unwrap();
            self.pka.dmem_write(u2_pub_key_z.len(), &u2_pub_key_z, Ecc384::PKA_Z1_ADDR).unwrap();

            // Write to PKA approximation of 1/P and command "PointAdd"
            self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
            self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
            self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_PA_VAL)});

            // Initialize (u1_G + u2_pubkey) computation in PKA
            self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
            self.pka.wait_for_done().unwrap();

            // Read (u1_G + u2_pubkey) data
            self.pka.dmem_read(r_proj_x.len(), Ecc384::PKA_RESX_ADDR, &mut r_proj_x).unwrap();
            self.pka.dmem_read(r_proj_z.len(), Ecc384::PKA_RESZ_ADDR, &mut r_proj_z).unwrap();
        } else {
            r_proj_x = u2_pub_key_x;
            r_proj_z = u2_pub_key_z;
        }

        // Write to PKA approximation of 1/P and command "ModInv"
        self.pka.dmem_write(r_proj_z.len(), &r_proj_z, Ecc384::PKA_MINV_OP_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MI_VAL)});

        // Initialize (1 / R(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read (1 / R(z)) data
        let mut z_inv = [0; 12];
        self.pka.dmem_read(z_inv.len(), Ecc384::PKA_MINV_RES_ADDR, &mut z_inv).unwrap();

        // Write to PKA approximation of 1/P and command "ModMult"
        self.pka.dmem_write(r_proj_x.len(), &r_proj_x, Ecc384::PKA_MMUL_OP1_ADDR).unwrap();
        self.pka.registers.n_inv_0().write(|w| unsafe {w.bits(Ecc384::PKA_NI_0_VAL)});
        self.pka.registers.n_inv_1().write(|w| unsafe {w.bits(Ecc384::PKA_NI_1_VAL)});
        self.pka.registers.command().write(|w| unsafe {w.bits(Ecc384::PKA_ENTR_MM_VAL)});

        // Initialize (R(x) / R(z)) computation in PKA
        self.pka.registers.ctrl().write(|w| unsafe {w.bits(Ecc384::PKA_CTRL_VAL)});
        self.pka.wait_for_done().unwrap();

        // Read Rx = (R(x) / R(z)) data
        let mut verify_r = [0; 12];
        self.pka.dmem_read(verify_r.len(), Ecc384::PKA_MMUL_RES_ADDR, &mut verify_r).unwrap();

        verify_r.reverse();

        let verify_r = Array4x12::new(verify_r);

        self.zeroize_internal();

        Ok(verify_r)
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.ecc.regs_mut().ctrl().write(|w| w.zeroize(true));
    }

    /// Zeroize the hardware registers.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// The caller must be certain that the results of any pending cryptographic
    /// operations will not be used after this function is called.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn zeroize() {
        let mut ecc = EccReg::new();
        ecc.regs_mut().ctrl().write(|w| w.zeroize(true));
    }
}

/// ECC-384 key access error trait
trait Ecc384KeyAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError;

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError;

    /// Convert to read private key operation error
    fn into_read_priv_key_err(self) -> CaliptraError;

    /// Convert to write private key operation error
    fn into_write_priv_key_err(self) -> CaliptraError;
}

impl Ecc384KeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_seed_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_SEED_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_SEED_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_SEED_KV_UNKNOWN,
        }
    }

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_DATA_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_DATA_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_DATA_KV_UNKNOWN,
        }
    }

    /// Convert to reads private key operation error
    fn into_read_priv_key_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_READ_PRIV_KEY_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_READ_PRIV_KEY_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_READ_PRIV_KEY_KV_UNKNOWN,
        }
    }

    /// Convert to write private key operation error
    fn into_write_priv_key_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_ECC384_WRITE_PRIV_KEY_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_ECC384_WRITE_PRIV_KEY_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_ECC384_WRITE_PRIV_KEY_KV_UNKNOWN,
        }
    }
}
