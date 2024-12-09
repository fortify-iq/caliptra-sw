/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains API for SHA-256 Cryptography operations

--*/

use core::{marker::PhantomData, usize};

use crate::{ Array4x8, CaliptraError, CaliptraResult};

use fortimac_hal::{FortimacErr, Fortimac256};
pub use fortimac_hal::{FortimacPeriph as Sha256Periph, FortimacReg as Sha256Reg};

// TODO: Fortimac requires seed, consider replacing with prng
const SEED: u32 = 0;
const SHA256_MAX_DATA_SIZE: usize = 1024 * 1024;

pub trait Sha256DigestOp<'a> {
    fn update(&mut self, data: &[u8]) -> CaliptraResult<()>;
    fn finalize(self, digest: &mut Array4x8) -> CaliptraResult<()>;
}

pub trait Sha256Alg {
    type DigestOp<'a>: Sha256DigestOp<'a>
    where
        Self: 'a;

    fn digest_init(&mut self) -> CaliptraResult<Self::DigestOp<'_>>;
    fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x8>;
}

pub struct Sha256 {
    sha256: Sha256Reg,
}

impl Sha256 {
    pub fn new(sha256: Sha256Reg) -> Self {
        Self { sha256 }
    }
}

impl Sha256Alg for Sha256 {
    type DigestOp<'a> = Sha256DigestOpHw<'a>;

    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha256Digest` - Object representing the digest operation
    fn digest_init(&mut self) -> CaliptraResult<Sha256DigestOpHw<'_>> {
        let engine = Fortimac256::new_sha(unsafe{Sha256Reg::steal()}, SEED);
        let op = Sha256DigestOpHw {
            _marker: PhantomData,
            sha: engine,
            data_size: 0,
        };

        Ok(op)
    }

    /// Calculate the digest of the buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the digest over
    fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x8> {
        // Check if the buffer is not large
        if buf.len() > SHA256_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA256_MAX_DATA);
        }

        let sha = Fortimac256::new_sha(unsafe{Sha256Reg::steal()}, SEED);

        let mut digest = [0; 32];
        sha.digest(buf, &mut digest).map_err(|err| err.into_caliptra_err())?;

        self.zeroize_internal();

        Ok(Array4x8::from(digest))
    }
}
impl Sha256 {
    /// Take a raw sha256 digest of 0 or more 64-byte blocks of memory. Unlike
    /// digest(), the each word is passed to the sha256 peripheral without
    /// byte-swapping to reverse the peripheral's big-endian words. This means the
    /// hash will be measured with the byte-swapped value of each word.
    ///
    /// # Safety
    ///
    /// The caller is responsible for ensuring that the safety requirements of
    /// [`core::ptr::read`] are valid for every value between `ptr.add(0)` and
    /// `ptr.add(n_blocks - 1)`.
    #[inline(always)]
    pub unsafe fn digest_blocks_raw(
        &mut self,
        mut ptr: *const [u32; 16],
        n_blocks: usize,
    ) -> CaliptraResult<Array4x8> {
        let mut sha = Fortimac256::new_sha(unsafe{Sha256Reg::steal()}, SEED);

        for _ in 0..n_blocks {
            let block = Self::words_to_bytes_64(ptr.read());

            sha.update(&block).map_err(|err| err.into_caliptra_err())?;

            ptr = ptr.wrapping_add(1);
        }

        let mut digest_bytes = [0; 32];
        sha.finalize(&mut digest_bytes).map_err(|err| err.into_caliptra_err())?;

        Ok(Array4x8::from(digest_bytes))
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        unsafe { self.sha256.cfg().write_with_zero(|w| w.srst().set_bit()) };
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
        let sha256 = Sha256Reg::steal();
        sha256.cfg().write_with_zero(|w| w.srst().set_bit());
    }

    /// Converts word array to byte array
    fn words_to_bytes_64(words: [u32; 16]) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (chunk, word) in bytes.chunks_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        bytes
    }
}

/// Multi step SHA-256 digest operation
pub struct Sha256DigestOpHw<'a> {
    /// Keep the original behaviour
    _marker: PhantomData<&'a ()>,

    /// SHA-256 Engine
    sha: Fortimac256,

    /// Data size
    data_size: usize,
}

impl<'a> Sha256DigestOp<'a> for Sha256DigestOpHw<'a> {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.data_size + data.len() > SHA256_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA256_MAX_DATA);
        }

        self.sha.update(data).map_err(|err| err.into_caliptra_err())?;

        Ok(())
    }

    /// Finalize the digest operations
    fn finalize(self, digest: &mut Array4x8) -> CaliptraResult<()> {
        let mut digest_bytes = [0; 32];
        self.sha.finalize(&mut digest_bytes).map_err(|err| err.into_caliptra_err())?;
        *digest = Array4x8::from(digest_bytes);

        Ok(())
    }
}

/// SHA-256 Fortimac error trait
trait Sha256FortimacErr {
    fn into_caliptra_err(self) -> CaliptraError;
}

impl Sha256FortimacErr for FortimacErr {
    /// Convert Fortimac errors to Caliptra during processing
    fn into_caliptra_err(self) -> CaliptraError {
        match self {
            FortimacErr::InvalidState => CaliptraError::DRIVER_SHA256_INVALID_STATE,
            FortimacErr::DataProc => CaliptraError::DRIVER_SHA256_DATA_PROC,
            FortimacErr::FaultInj => CaliptraError::DRIVER_SHA256_FAULT_INJ,
        }
    }
}
