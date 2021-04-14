/*******************************************************************************
*   (c) 2020 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
//! Support library for Dfinity Ledger Nano S/X apps

#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

use std::str;

use ledger_transport::{APDUCommand, APDUErrorCodes, APDUTransport};
use ledger_zondax_generic::{
    map_apdu_error_description, AppInfo, ChunkPayloadType, DeviceInfo, LedgerAppError, Version,
};
use log::info;
use zx_bip44::BIP44Path;

const INS_GET_ADDR: u8 = 0x01;
const INS_SIGN: u8 = 0x02;

const PK_LEN: usize = 65;
const ADDR_LEN: usize = 29;
const ADDR_TEXT_LEN: usize = 20;

const PREHASH_LEN: usize = 43;
const SIG_LEN: usize = 65;

/// Ledger App
pub struct DfinityApp {
    pub(crate) apdu_transport: APDUTransport,
    pub(crate) cla: u8,
}

/// Ledger application mode
pub enum AppMode {
    /// Standard Mode - Normal App
    Standard = 0,
    /// Testing Mode - Only for testing purposes
    Testing = 1,
}

type PublicKey = [u8; PK_LEN];
type Address = [u8; ADDR_LEN];

/// Dfinity address (includes pubkey and the corresponding address)
pub struct DfinityAddress {
    /// Public Key
    pub public_key: PublicKey,
    /// Address
    pub address: Address,
    /// Textual representation of address
    pub address_textual: String,
}

/// Dfinity Signature
pub struct Signature {
    /// Public Key
    pub pre_signature_hash: [u8; PREHASH_LEN],
    /// Signature RSV
    pub rsv: [u8; 65],
}

impl DfinityApp {
    /// Connect to the Ledger App
    pub fn new(apdu_transport: APDUTransport, cla: u8) -> Self {
        DfinityApp {
            apdu_transport,
            cla,
        }
    }

    /// Retrieve the app version
    pub async fn get_version(&self) -> Result<Version, LedgerAppError> {
        ledger_zondax_generic::get_version(self.cla, &self.apdu_transport).await
    }

    /// Retrieve the app info
    pub async fn get_app_info(&self) -> Result<AppInfo, LedgerAppError> {
        ledger_zondax_generic::get_app_info(&self.apdu_transport).await
    }

    /// Retrieve the device info
    pub async fn get_device_info(&self) -> Result<DeviceInfo, LedgerAppError> {
        ledger_zondax_generic::get_device_info(&self.apdu_transport).await
    }

    /// Retrieves the public key and address
    pub async fn get_address(
        &self,
        path: &BIP44Path,
        require_confirmation: bool,
    ) -> Result<DfinityAddress, LedgerAppError> {
        let serialized_path = path.serialize();
        let p1 = if require_confirmation { 1 } else { 0 };

        let command = APDUCommand {
            cla: self.cla,
            ins: INS_GET_ADDR,
            p1,
            p2: 0x00,
            data: serialized_path,
        };

        match self.apdu_transport.exchange(&command).await {
            Ok(response) => {
                if response.retcode != APDUErrorCodes::NoError as u16 {
                    info!("get_address: retcode={:X?}", response.retcode);
                    return Err(LedgerAppError::AppSpecific(
                        response.retcode,
                        map_apdu_error_description(response.retcode).to_string(),
                    ));
                }

                if response.data.len() < PK_LEN + ADDR_LEN + ADDR_TEXT_LEN {
                    return Err(LedgerAppError::InvalidPK);
                }

                let mut address = DfinityAddress {
                    public_key: [0; PK_LEN],
                    address: [0; ADDR_LEN],
                    address_textual: "".to_string(),
                };

                address.public_key.copy_from_slice(&response.data[..PK_LEN]);
                address
                    .address
                    .copy_from_slice(&response.data[PK_LEN..PK_LEN + ADDR_LEN]);
                address.address_textual = str::from_utf8(&response.data[PK_LEN + ADDR_LEN..])
                    .map_err(|_e| LedgerAppError::Utf8)?
                    .to_owned();
                address.address_textual = address
                    .address_textual
                    .chars()
                    .enumerate()
                    .flat_map(|(i, c)| {
                        if i != 0 && i % 5 == 0 {
                            Some('-')
                        } else {
                            None
                        }
                        .into_iter()
                        .chain(std::iter::once(c))
                    })
                    .collect::<String>();
                Ok(address)
            }

            Err(e) => Err(LedgerAppError::TransportError(e)),
        }
    }

    /// Sign a transaction
    pub async fn sign(
        &self,
        path: &BIP44Path,
        message: &[u8],
    ) -> Result<Signature, LedgerAppError> {
        let serialized_path = path.serialize();
        let start_command = APDUCommand {
            cla: self.cla,
            ins: INS_SIGN,
            p1: ChunkPayloadType::Init as u8,
            p2: 0x00,
            data: serialized_path,
        };

        let response =
            ledger_zondax_generic::send_chunks(&self.apdu_transport, &start_command, message)
                .await?;

        if response.data.is_empty() && response.retcode == APDUErrorCodes::NoError as u16 {
            return Err(LedgerAppError::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() <= PREHASH_LEN + SIG_LEN + 2 {
            return Err(LedgerAppError::InvalidSignature);
        }

        let mut sig: Signature = Signature {
            pre_signature_hash: [0; PREHASH_LEN],
            rsv: [0; SIG_LEN],
        };
        sig.pre_signature_hash
            .copy_from_slice(&response.data[..PREHASH_LEN]);
        sig.rsv
            .copy_from_slice(&response.data[PREHASH_LEN..PREHASH_LEN + SIG_LEN]);

        Ok(sig)
    }
}
