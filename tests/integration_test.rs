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
}
