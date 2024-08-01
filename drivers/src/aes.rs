use caliptra_error::{CaliptraError, CaliptraResult};
use forticrypt_hal::{Forticrypt128, Forticrypt192, Forticrypt256, ForticryptErr};

pub use forticrypt_hal::{
    ForticryptPeriph as AesPeriph, ForticryptReg as AesReg, Mode as AesMode, Op as AesOp,
};

pub struct Aes128 {
    aes: Forticrypt128,
}

impl Aes128 {
    pub fn new(
        registers: AesReg,
        op: AesOp,
        mode: AesMode,
        key: Option<&[u8]>,
        ivnonce: Option<[u8; 16]>,
        seed: [u8; 32],
    ) -> CaliptraResult<Self> {
        let aes = Forticrypt128::new(registers, op, mode, key, ivnonce, seed)
            .map_err(|err| err.into_caliptra_err())?;

        Ok(Self { aes })
    }

    pub fn update_seed(&self, seed: [u8; 32]) {
        self.aes.update_seed(seed)
    }

    pub fn tag(&self) -> &Option<[u8; 16]> {
        self.aes.tag()
    }

    pub fn run_core_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> CaliptraResult<()> {
        match self.aes.run_core_b2b(input, output, aad) {
            Ok(ok) => {
                self.zeroize_internal();
                Ok(ok)
            }
            Err(err) => Err(err.into_caliptra_err()),
        }
    }

    fn zeroize_internal(&self) {
        self.aes.send_reset()
    }

    pub unsafe fn zeroize() {
        let aes = AesReg::steal();
        aes.cfg().write_with_zero(|w| w.srst().set_bit());
    }
}

pub struct Aes192 {
    aes: Forticrypt192,
}

impl Aes192 {
    pub fn new(
        registers: AesReg,
        op: AesOp,
        mode: AesMode,
        key: Option<&[u8]>,
        ivnonce: Option<[u8; 16]>,
        seed: [u8; 32],
    ) -> CaliptraResult<Self> {
        let aes = Forticrypt192::new(registers, op, mode, key, ivnonce, seed)
            .map_err(|err| err.into_caliptra_err())?;

        Ok(Self { aes })
    }

    pub fn update_seed(&self, seed: [u8; 32]) {
        self.aes.update_seed(seed)
    }

    pub fn tag(&self) -> &Option<[u8; 16]> {
        self.aes.tag()
    }

    pub fn run_core_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> CaliptraResult<()> {
        match self.aes.run_core_b2b(input, output, aad) {
            Ok(ok) => {
                self.zeroize_internal();
                Ok(ok)
            }
            Err(err) => Err(err.into_caliptra_err()),
        }
    }

    fn zeroize_internal(&self) {
        self.aes.send_reset()
    }

    pub unsafe fn zeroize() {
        let aes = AesReg::steal();
        aes.cfg().write_with_zero(|w| w.srst().set_bit());
    }
}

pub struct Aes256 {
    aes: Forticrypt256,
}

impl Aes256 {
    pub fn new(
        registers: AesReg,
        op: AesOp,
        mode: AesMode,
        key: Option<&[u8]>,
        ivnonce: Option<[u8; 16]>,
        seed: [u8; 32],
    ) -> CaliptraResult<Self> {
        let aes = Forticrypt256::new(registers, op, mode, key, ivnonce, seed)
            .map_err(|err| err.into_caliptra_err())?;

        Ok(Self { aes })
    }

    pub fn update_seed(&self, seed: [u8; 32]) {
        self.aes.update_seed(seed)
    }

    pub fn tag(&self) -> &Option<[u8; 16]> {
        self.aes.tag()
    }

    pub fn run_core_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> CaliptraResult<()> {
        match self.aes.run_core_b2b(input, output, aad) {
            Ok(ok) => {
                self.zeroize_internal();
                Ok(ok)
            }
            Err(err) => Err(err.into_caliptra_err()),
        }
    }

    fn zeroize_internal(&self) {
        self.aes.send_reset()
    }

    pub unsafe fn zeroize() {
        let aes = AesReg::steal();
        aes.cfg().write_with_zero(|w| w.srst().set_bit());
    }
}

/// AES Forticrypt error trait
trait AesForticryptErr {
    fn into_caliptra_err(self) -> CaliptraError;
}

impl AesForticryptErr for ForticryptErr {
    /// Convert Forticrypt errors to Caliptra during processing
    fn into_caliptra_err(self) -> CaliptraError {
        match self {
            ForticryptErr::ExtraAad => CaliptraError::DRIVER_AES_EXTRA_AAD,
            ForticryptErr::ExtraIvNonce => CaliptraError::DRIVER_AES_EXTRA_IV_NONCE,
            ForticryptErr::EmptyInput => CaliptraError::DRIVER_AES_EMPTY_INPUT,
            ForticryptErr::NonEmptyCmacOutput => CaliptraError::DRIVER_AES_NON_EMPTY_CMAC_OUTPUT,
            ForticryptErr::InvalidKeySize => CaliptraError::DRIVER_AES_INVALID_KEY_SIZE,
            ForticryptErr::InvalidCmacOp => CaliptraError::DRIVER_AES_INVALID_CMAC_OP,
            ForticryptErr::InvalidXtsAes => CaliptraError::DRIVER_AES_INVALID_XTS_AES,
            ForticryptErr::MissingAad => CaliptraError::DRIVER_AES_MISSING_AAD,
            ForticryptErr::MissingIvNonce => CaliptraError::DRIVER_AES_MISSING_IV_NONCE,
            ForticryptErr::UnpaddedInput => CaliptraError::DRIVER_AES_UNPADDED_INPUT,
            ForticryptErr::UnequalInOutSizes => CaliptraError::DRIVER_AES_UNEQUAL_IN_OUT_SIZES,
        }
    }
}
