#![crate_name = "sealeddataenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tseal::SgxSealedData;
use sgx_types::{sgx_attributes_t, sgx_sealed_data_t, sgx_status_t};

use sgx_tstd::{
    io::{Read, Write},
    sgxfs::SgxFile,
    slice, str,
    string::String,
    vec::Vec,
};

const SEALED_LOG_SIZE: usize = 640;

const DATAFILE: &'static str = "account_data.db";

extern "C" {
    pub fn file_write(
        retval: *mut sgx_status_t,
        file_name: *const u8,
        file_len: usize,
        content: *const u8,
        content_len: usize,
    ) -> sgx_status_t;
    pub fn file_read(
        retval: *mut *const u8,
        file_name: *const u8,
        file_len: usize,
        data_len: *mut u64,
    ) -> *const u8;
    pub fn test_ocall(retval: *mut sgx_status_t, slen: u8) -> sgx_status_t;
}

#[derive(Debug, Clone)]
pub struct Account {
    username: Option<String>,
    deposit: u64,
}

impl Account {
    fn new(username: Option<String>) -> Self {
        Self {
            username: username,
            deposit: 0,
        }
    }
    fn update_money(&self) {
        let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let dbname = format!(
            "{}.db",
            self.username
                .clone()
                .unwrap_or_else(|| panic!("deposit self error."))
        );
        let data = format!(
            "{},{}",
            self.username
                .clone()
                .unwrap_or_else(|| panic!("deposit self error.")),
            self.deposit
        );
        seal_data(
            &(dbname.as_bytes())[0] as *const u8,
            dbname.len(),
            &(data.as_bytes())[0] as *const u8,
            data.len(),
        );
        // unsafe {
        //     file_write(
        //         &mut retval as *mut sgx_status_t,
        //         &(dbname.as_bytes())[0] as *const u8,
        //         dbname.len(),
        //         &(data.as_bytes())[0] as *const u8,
        //         data.len(),
        //     );
        // };
        // assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
    }
    pub fn register(username: String) -> Self {
        let account = Self::new(Some(username.clone()));
        let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let dbname = format!("{}.db", &username[..]);
        let data = format!("{},0", username);
        seal_data(
            &(dbname.as_bytes())[0] as *const u8,
            dbname.len(),
            &(data.as_bytes())[0] as *const u8,
            data.len(),
        );
        // unsafe {
        //     file_write(
        //         &mut retval as *mut sgx_status_t,
        //         &(dbname.as_bytes())[0] as *const u8,
        //         dbname.len(),
        //         &(data.as_bytes())[0] as *const u8,
        //         data.len(),
        //     );
        // };
        Self {
            username: Some(username),
            deposit: 0,
        }
    }
    pub fn login(username: String) -> Self {
        let account = Self::new(Some(username.clone()));
        let dbname = format!("{}.db", username);
        let mut retval = 0 as *mut u8;
        let mut content_vec: Vec<u8> = vec![];
        let mut data_len: usize = 0;
        let mut p_unseal_data = vec![];
        unseal_data(
            &(dbname.as_bytes())[0] as *const u8,
            dbname.len(),
            &mut p_unseal_data,
            &mut data_len as *mut usize,
        );
        // println!("login middle unseal_data_{} {:?}", p_unseal_data);
        // unsafe {
        //     file_read(
        //         &mut retval as *mut *mut u8,
        //         &(dbname.as_bytes())[0],
        //         dbname.len(),
        //         &mut data_len as *mut u64,
        //     );
        // };
        // unsafe {
        //     for i in 0..data_len as usize {
        //         let c: u8 = *p_unseal_data.add(i);
        //         content_vec.push(*p_unseal_data.add(i));
        //     }
        // };
        let data = String::from_utf8(p_unseal_data).unwrap();
        let account_info = data.split(',').collect::<Vec<&str>>();
        if (account_info.len() != 2) {
            println!("data is invalid in login.");
        }
        Self {
            username: Some(String::from(account_info[0])),
            deposit: account_info[1].parse().unwrap_or_else(|_| {
                panic!(
                    "login deposit error: {}, len: {}",
                    account_info[1],
                    account_info[1].len()
                )
            }),
        }
    }
    pub fn deposit(&mut self, add_money: u64) {
        self.deposit += add_money;
        self.update_money();
    }
    pub fn pullout(&mut self, sub_money: u64) -> bool {
        if (self.deposit < sub_money) {
            return false;
        }
        self.deposit -= sub_money;
        self.update_money();
        return true;
    }
}

#[no_mangle]
pub extern "C" fn user_register(username: *const u8, username_len: usize) -> sgx_status_t {
    let name = unsafe { slice::from_raw_parts(username, username_len) };
    Account::register(
        String::from_utf8(name.to_vec()).unwrap_or_else(|_| panic!("user_register name error.")),
    );
    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn deposit_ecall(
    username: *const u8,
    username_len: usize,
    add_money: u64,
) -> sgx_status_t {
    let name = unsafe { slice::from_raw_parts(username, username_len) };
    let mut account = Account::login(
        String::from_utf8(name.to_vec()).unwrap_or_else(|_| panic!("user_register name error.")),
    );
    account.deposit(add_money);
    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn pullout_ecall(
    username: *const u8,
    username_len: usize,
    sub_money: u64,
) -> sgx_status_t {
    let name = unsafe { slice::from_raw_parts(username, username_len) };
    let mut account = Account::login(
        String::from_utf8(name.to_vec()).unwrap_or_else(|_| panic!("user_register name error.")),
    );
    let ret = account.pullout(sub_money);
    if ret {
        return sgx_status_t::SGX_SUCCESS;
    } else {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
}

#[no_mangle]
pub extern "C" fn deposit_print_ecall(username: *const u8, username_len: usize) -> sgx_status_t {
    let name = unsafe { slice::from_raw_parts(username, username_len) };
    let account = Account::login(
        String::from_utf8(name.to_vec()).unwrap_or_else(|_| panic!("user_register name error.")),
    );
    println!("[現在の預金額]: {}円", account.deposit);
    return sgx_status_t::SGX_SUCCESS;
}

fn seal_data(
    dbname: *const u8,
    dbname_len: usize,
    message: *const u8,
    message_len: usize,
) -> sgx_status_t {
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

    let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;

    unsafe {
        file_write(
            &mut retval as *mut sgx_status_t,
            dbname,
            dbname_len,
            sealed_log.as_ptr() as *const u8,
            SEALED_LOG_SIZE,
        );
    };

    sgx_status_t::SGX_SUCCESS
}

fn unseal_data(
    dbname: *const u8,
    dbname_len: usize,
    p_unseal_data: &mut Vec<u8>,
    unseal_data_len: *mut usize,
) -> sgx_status_t {
    let mut sealed_log = [0_u8; SEALED_LOG_SIZE];

    let mut retval = 0 as *const u8;
    let mut sealed_len: u64 = 0;

    unsafe {
        file_read(
            &mut retval as *mut *const u8,
            dbname,
            dbname_len,
            &mut sealed_len as *mut u64,
        );
    };

    let raw_sealed_log = retval as *mut sgx_sealed_data_t;

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

    for i in 0..data.len() {
        p_unseal_data.push(data[i]);
    }

    unsafe {
        // *p_unseal_data = data.as_ptr() as *mut u8;
        *unseal_data_len = data.len();
    }

    // unsafe {
    //     println!("p_unseal_data: {:?}, unseal_size: {}, data: {:?}", p_unseal_data, *unseal_data_len, data);
    //     println!("{:?}, ", str::from_utf8(data).unwrap());
    // }

    sgx_status_t::SGX_SUCCESS
}
