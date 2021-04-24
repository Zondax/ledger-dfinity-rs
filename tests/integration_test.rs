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

    use secp256k1::{Message, PublicKey, Secp256k1, Signature};
    use sha2::Digest;

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
            hex::encode(resp.principal),
            "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302"
        );
        assert_eq!(
            hex::encode(resp.address),
            "4f3d4b40cdb852732601fccf8bd24dffe44957a647cb867913e982d98cf85676"
        );
        assert_eq!(
            resp.principal_textual,
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
            hex::encode(resp.principal),
            "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302"
        );
        assert_eq!(
            hex::encode(resp.address),
            "4f3d4b40cdb852732601fccf8bd24dffe44957a647cb867913e982d98cf85676"
        );
        assert_eq!(
            resp.principal_textual,
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

        let txblob = "d9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550f5390d960c6e52f489155a4309da03da6e696e67726573735f6578706972791b1674c5e29ec9c2106673656e646572581d7bdd7f75eea6fcf58001e0dfb7d718b9e8f2c3b01e1ccec9ab305aad026b63616e69737465725f69644a000000000000000201016b6d6574686f645f6e616d656473656e646361726758560a0012050a0308e8071a0308890122220a2001010101010101010101010101010101010101010101010101010101010101012a220a2035548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b1276d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f7369675840de5bccbb0a0173c432cd58ea4495d4d1e122d6ce04e31dcf63217f3d3a9b73130dc9bbf3b10e61c8db8bf8800bb4649e27786e5bc9418838c95864be28487a6a";

        let message = hex::decode(txblob).unwrap();

        let req = app
            .sign(
                &BIP44Path::from_string("m/44'/223'/0'/0/0").unwrap(),
                &message,
            )
            .await;

        let resp = req.unwrap();

        assert_eq!(hex::encode(resp.pre_signature_hash),"0a69632d726571756573747058c3bd4323237852f94f4dfa923e3f26080679619140014356f3d6c48e674b");

        let pubkey = PublicKey::from_slice(&hex::decode("0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835").unwrap()).unwrap();

        let signature = Signature::from_compact(&resp.rs);

        let digest =
            Message::from_slice(sha2::Sha256::digest(&resp.pre_signature_hash).as_slice()).unwrap();

        assert!(Secp256k1::new()
            .verify(&digest, &signature.unwrap(), &pubkey)
            .is_ok());
    }

    #[async_test]
    async fn sign_stateread() {
        init_logging();

        let transport = APDUTransport {
            transport_wrapper: Box::new(ledger::TransportNativeHID::new().unwrap()),
        };
        let app = new_dfinity_app(transport);

        let txblob = "d9d9f7a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b1674c5e2b4d947b06673656e646572581d7bdd7f75eea6fcf58001e0dfb7d718b9e8f2c3b01e1ccec9ab305aad0265706174687381824e726571756573745f73746174757358207058c3bd4323237852f94f4dfa923e3f26080679619140014356f3d6c48e674b6d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f73696758403c850f1f7d6ae07777ca077dbb7fe2a21d9e5c38494dc17d2e1736ed760d1db222688979769d978153ee4e0420af5c5052f0de5acba20e6a0865414f048ffa61";

        let message = hex::decode(txblob).unwrap();

        let req = app
            .sign(
                &BIP44Path::from_string("m/44'/223'/0'/0/0").unwrap(),
                &message,
            )
            .await;

        let resp = req.unwrap();

        assert_eq!(hex::encode(resp.pre_signature_hash),"0a69632d7265717565737494a6b4c7dd97a1d04f7428b26ecca2b55c049fa473c23f0792bf5267bc45033f");

        let pubkey = PublicKey::from_slice(&hex::decode("0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835").unwrap()).unwrap();

        let signature = Signature::from_compact(&resp.rs);

        let digest =
            Message::from_slice(sha2::Sha256::digest(&resp.pre_signature_hash).as_slice()).unwrap();

        assert!(Secp256k1::new()
            .verify(&digest, &signature.unwrap(), &pubkey)
            .is_ok());
    }
}
