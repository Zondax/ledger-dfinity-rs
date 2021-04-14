/*******************************************************************************
*   (c) 2018-2020 Zondax GmbH
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
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

extern crate hex;
extern crate ledger_dfinity;
#[macro_use]
extern crate serial_test;
extern crate sha2;

#[cfg(test)]
mod integration_tests {
    use env_logger::Env;
    use futures_await_test::async_test;
    use ledger_dfinity::{new_dfinity_app, APDUTransport};
    use zx_bip44::BIP44Path;

    fn init_logging() {
        let _ = env_logger::from_env(Env::default().default_filter_or("info"))
            .is_test(true)
            .try_init();
    }

    #[async_test]
    #[serial]
    async fn version() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = new_dfinity_app(transport);

        let resp = app.get_version().await.unwrap();

        println!("mode  {}", resp.mode);
        println!("major {}", resp.major);
        println!("minor {}", resp.minor);
        println!("patch {}", resp.patch);
        println!("locked {}", resp.locked);

        // assert!(resp.major > 0);
        // assert!(resp.minor > 0);
    }

    #[async_test]
    async fn get_address() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = new_dfinity_app(transport);

        let resp = app
            .get_address(&BIP44Path::from_string("m/44'/223'/0'/0/0").unwrap(), false)
            .await
            .unwrap();

        assert_eq!(hex::encode(resp.public_key),"0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835");
        assert_eq!(
            hex::encode(resp.address),
            "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302"
        );
        assert_eq!(
            resp.address_textual,
            "5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe".to_string()
        );
    }

    #[async_test]
    async fn show_address() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = new_dfinity_app(transport);

        let req = app
            .get_address(&BIP44Path::from_string("m/44'/223'/0'/0/0").unwrap(), true)
            .await;

        let resp = req.unwrap();

        assert_eq!(hex::encode(resp.public_key),"0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835");
        assert_eq!(
            hex::encode(resp.address),
            "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302"
        );
        assert_eq!(
            resp.address_textual,
            "5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe".to_string()
        );
    }

    #[async_test]
    async fn sign_tokentransfer() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = new_dfinity_app(transport);

        let txblob = "d9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550e063ee93160f37ee2216b6a2a28119a46e696e67726573735f6578706972791b166b1ab6ec9c35086673656e646572581d45717a3a0e68fceef546ac77bac551754b48dbb1fccfa180673030b6026b63616e69737465725f69644a000000000000000a01016b6d6574686f645f6e616d656473656e646361726758474449444c026c04fbca0171c6fcb60201ba89e5c2047cd8a38ca80d016c01b1dfb793047c01001b72776c67742d69696161612d61616161612d61616161612d636169880100e8076d73656e6465725f7075626b6579582c302a300506032b6570032100e29472cb531fdb17386dae5f5a6481b661eb3ac4b4982c638c91f7716c2c96e76a73656e6465725f736967584084dc1f2e7338eac3eae5967ddf6074a8f6c2d98e598f481a807569c9219b94d4175bed43e8d25bde1b411c4f50b9fe23e1c521ec53f3c2f80fa4621b27292208";

        let message = hex::decode(txblob).unwrap();

        let req = app
            .sign(
                &BIP44Path::from_string("m/44'/223'/0'/0/0").unwrap(),
                &message,
                0x00,
            )
            .await;

        let resp = req.unwrap();

        assert_eq!(hex::encode(resp.pre_signature_hash),"0a69632d72657175657374bf5bae8c2b6be8103a070e6d2240c18788c10a94ba68990f8c7e7acecb8b8c34");
    }

    #[async_test]
    async fn sign_stateread() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = new_dfinity_app(transport);

        let txblob = "d9d9f7a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b166f4469eeb674586673656e646572581d45717a3a0e68fceef546ac77bac551754b48dbb1fccfa180673030b60265706174687381824e726571756573745f737461747573582062af1451c511bc05819de49a5e271ad77d4cd9624da4a3bdf2e45d0ae35e72826d73656e6465725f7075626b6579582c302a300506032b6570032100e29472cb531fdb17386dae5f5a6481b661eb3ac4b4982c638c91f7716c2c96e76a73656e6465725f73696758401a48a2202c5d968a693b310c71207577c7c9f43d6596f4e828e47587170e60faf4171982e3fcad7109ccada265ffd3d2132b0d8a26e8013478b0ded5861d1d03";

        let message = hex::decode(txblob).unwrap();

        let req = app
            .sign(
                &BIP44Path::from_string("m/44'/223'/0'/0/0").unwrap(),
                &message,
                0x01,
            )
            .await;

        let resp = req.unwrap();

        assert_eq!(hex::encode(resp.pre_signature_hash),"0a69632d72657175657374e9db309ae391d86190768bb57d6d5ab1e29e876a4f8dbc94bd71c198bc4d341b");
    }
}
