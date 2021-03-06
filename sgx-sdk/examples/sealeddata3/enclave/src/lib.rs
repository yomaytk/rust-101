#![crate_name = "sealeddataenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tseal::SgxSealedData;
use sgx_tstd::{
    io::{Read, Write},
    sgxfs::SgxFile,
    slice, str,
};
use sgx_types::{sgx_sealed_data_t, sgx_status_t};

const SEALED_LOG_SIZE: usize = 640;

#[no_mangle]
pub extern "C" fn seal_data(message: *const u8, message_len: usize) -> sgx_status_t {
    let message_slice = unsafe { slice::from_raw_parts(message, message_len) };

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, &message_slice);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let mut sealed_log: [u8; SEALED_LOG_SIZE] = [0; SEALED_LOG_SIZE];
    let p_sealed_log = sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t;
    let ret = unsafe { sealed_data.to_raw_sealed_data_t(p_sealed_log, SEALED_LOG_SIZE as u32) };

    if ret.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    unsafe {
        println!(
            "key_request.key_name: {}",
            (*p_sealed_log).key_request.key_name
        );
        println!(
            "key_request.key_policy: {}",
            (*p_sealed_log).key_request.key_policy
        );
        println!("plain_text_offset: {}", (*p_sealed_log).plain_text_offset);
        println!("payload_size: {}", (*p_sealed_log).aes_data.payload_size);
        println!(
            "payload_tag: {:?}",
            (*p_sealed_log).aes_data.payload_tag.to_vec()
        );
    }

    let mut file = match SgxFile::create("sgx_file") {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::create failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    let write_size = match file.write(&sealed_log) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::write failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    println!(
        "write file success, write size: {}, {:?}.",
        write_size, sealed_log
    );

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn unseal_data() -> sgx_status_t {
    let mut sealed_log = [0_u8; SEALED_LOG_SIZE];

    let mut file = match SgxFile::open("sgx_file") {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::open failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let read_size = match file.read(&mut sealed_log) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::read failed.");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    println!(
        "read file success, read size: {}, {:?}.",
        read_size, sealed_log
    );

    let raw_sealed_log = sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t;

    unsafe {
        println!(
            "key_request.key_name: {}",
            (*raw_sealed_log).key_request.key_name
        );
        println!(
            "key_request.key_policy: {}",
            (*raw_sealed_log).key_request.key_policy
        );
        println!("plain_text_offset: {}", (*raw_sealed_log).plain_text_offset);
        println!("payload_size: {}", (*raw_sealed_log).aes_data.payload_size);
        println!(
            "payload_tag: {:?}",
            (*raw_sealed_log).aes_data.payload_tag.to_vec()
        );
    }

    let opt = unsafe {
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(raw_sealed_log, SEALED_LOG_SIZE as u32)
    };
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let data = unsealed_data.get_decrypt_txt();

    println!("{:?}", data);
    println!("{:?}", str::from_utf8(data).unwrap());

    sgx_status_t::SGX_SUCCESS
}

// #[no_mangle]
// pub extern "C" fn create_sealeddata(message: *const u8, message_len: usize) -> sgx_status_t {
//     let message_slice = unsafe { slice::from_raw_parts(message, message_len) };

//     let attribute_mask = sgx_attributes_t {
//         flags: sgx_types::TSEAL_DEFAULT_FLAGSMASK,
//         xfrm: 0,
//     };
//     let aad: [u8; 0] = [0_u8; 0];
//     let result = SgxSealedData::<[u8]>::seal_data_ex(
//         sgx_types::SGX_KEYPOLICY_MRENCLAVE,
//         attribute_mask,
//         sgx_types::TSEAL_DEFAULT_MISCMASK,
//         &aad,
//         &message_slice,
//     );
//     let sealed_data = match result {
//         Ok(x) => x,
//         Err(ret) => {
//             return ret;
//         }
//     };

//     let mut sealed_log: [u8; SEALED_LOG_SIZE] = [0; SEALED_LOG_SIZE];
//     let p_sealed_log = sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t;
//     let ret = unsafe { sealed_data.to_raw_sealed_data_t(p_sealed_log, SEALED_LOG_SIZE as u32) };

//     if ret.is_none() {
//         return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
//     }

//     println!("{:?}", sealed_log);

//     // println!("debug:\n");
//     // {
//     //     println!("========================");
//     //     let username = String::from("nagatomi-san");
//     //     let mut account = Account::register(username);
//     //     println!("register: {:?}", account);
//     //     account.deposit(1200);
//     //     println!("deposit: {:?}", account);
//     //     println!("========================");
//     // }

//     // {
//     //     println!("++++++++++++++++++++++++");
//     //     let username = String::from("nagatomi-san");
//     //     let mut account = Account::login(username);
//     //     println!("login: {:?}", account);
//     //     account.deposit(2300);
//     //     println!("deposit: {:?}", account);
//     //     println!("++++++++++++++++++++++++");
//     // }

//     // {
//     //     println!("-----------------------");
//     //     let username = String::from("nagatomi");
//     //     let mut account = Account::login(username);
//     //     println!("login: {:?}", account);
//     //     account.pullout(1000);
//     //     println!("deposit: {:?}", account);
//     //     println!("-----------------------");
//     // }

//     // {
//     //     println!("========================");
//     //     let username = String::from("tatsumi");
//     //     let mut account = Account::register(username);
//     //     println!("register: {:?}", account);
//     //     account.deposit(1200);
//     //     println!("deposit: {:?}", account);
//     //     println!("========================");
//     // }

//     // unsafe { file_write(&mut retval as *mut sgx_status_t, &db_name[0] as *const u8, name.len(), &content[0] as *const u8, 13); };
//     // unsafe { test_ocall(&mut retval as *mut sgx_status_t, 100); };
//     // println!("ocall end\n.");

//     // unsafe {
//     //     println!(
//     //         "key_request.key_name: {}",
//     //         (*p_sealed_log).key_request.key_name
//     //     );
//     //     println!(
//     //         "key_request.key_policy: {}",
//     //         (*p_sealed_log).key_request.key_policy
//     //     );
//     //     println!("plain_text_offset: {}", (*p_sealed_log).plain_text_offset);
//     //     println!("payload_size: {}", (*p_sealed_log).aes_data.payload_size);
//     //     println!(
//     //         "payload_tag: {:?}",
//     //         (*p_sealed_log).aes_data.payload_tag.to_vec()
//     //     );
//     // }

//     let opt = unsafe {
//         SgxSealedData::<[u8]>::from_raw_sealed_data_t(p_sealed_log, SEALED_LOG_SIZE as u32)
//     };
//     let sealed_data = match opt {
//         Some(x) => x,
//         None => {
//             return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
//         }
//     };

//     let result = sealed_data.unseal_data();
//     let unsealed_data = match result {
//         Ok(x) => x,
//         Err(ret) => {
//             return ret;
//         }
//     };

//     let data = unsealed_data.get_decrypt_txt();

//     println!("{:?}, {}", data, data.len());
//     println!("{:?}", str::from_utf8(data).unwrap());

//     sgx_status_t::SGX_SUCCESS
// }
