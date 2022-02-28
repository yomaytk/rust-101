use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::fs::File;
use std::io::prelude::*;
use std::slice;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn user_register(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        username: *const u8,
        username_len: usize,
    ) -> sgx_status_t;
    fn deposit_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        username: *const u8,
        username_len: usize,
        add_money: u64,
    ) -> sgx_status_t;
    fn pullout_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        username: *const u8,
        username_len: usize,
        sub_money: u64,
    ) -> sgx_status_t;
    fn deposit_print_ecall(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        username: *const u8,
        username_len: usize,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn file_write(
    file_name: *const u8,
    file_len: usize,
    content: *const u8,
    content_len: usize,
) -> sgx_status_t {
    let file_str = unsafe { slice::from_raw_parts(file_name, file_len) };
    let content_str = unsafe { slice::from_raw_parts(content, content_len) };
    let file_string = String::from_utf8(file_str.to_vec()).unwrap();
    let mut file = File::create(file_string).unwrap();
    file.write_all(content_str).unwrap();
    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn file_read(
    file_name: *const u8,
    file_len: usize,
    data_len: *mut usize,
) -> *const u8 {
    let file_str = unsafe { slice::from_raw_parts(file_name, file_len) };
    let file_string = String::from_utf8(file_str.to_vec()).unwrap();
    let mut content = std::fs::read(file_string).unwrap();
    unsafe {
        *data_len = content.len();
    };
    let leak_content = content.leak();
    &leak_content[0]
}

#[no_mangle]
pub extern "C" fn test_ocall(slen: u8) -> sgx_status_t {
    return sgx_status_t::SGX_SUCCESS;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn input_line(input: &mut String) {
    std::io::stdin().read_line(input).unwrap();
    input.pop();
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            // println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            // println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let mut input = String::new();
    let mut state = 0;
    let mut username = String::new();

    loop {
        input.clear();
        if state == 0 {
            println!("口座新規登録の方は１，ログインの方は２を押してください。");
            input_line(&mut input);
            state = input.parse().unwrap();
        } else if state == 1 || state == 2 {
            println!("登録名を入力してください。");
            input_line(&mut input);
            username = input.clone();
            if state == 1 {
                unsafe {
                    user_register(
                        enclave.geteid(),
                        &mut retval,
                        input.as_ptr() as *const u8,
                        input.len(),
                    )
                };
            }
            assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
            state = 3;
        } else if state == 3 {
            unsafe {
                deposit_print_ecall(
                    enclave.geteid(),
                    &mut retval,
                    username.as_ptr() as *const u8,
                    username.len(),
                );
            }
            println!("引き出す場合は４、預ける場合は５を押してください。取引を終了する場合は９を押してください。");
            input_line(&mut input);
            state = input.parse().unwrap();
        } else if state == 4 {
            println!("引き出す金額を入力してください。");
            input_line(&mut input);
            let add_money: u64 = input.parse().unwrap();
            unsafe {
                pullout_ecall(
                    enclave.geteid(),
                    &mut retval,
                    username.as_ptr() as *const u8,
                    username.len(),
                    add_money,
                )
            };
            if (retval == sgx_status_t::SGX_ERROR_UNEXPECTED) {
                println!("残高が足りません。やり直してください。");
                unsafe {
                    deposit_print_ecall(
                        enclave.geteid(),
                        &mut retval,
                        username.as_ptr() as *const u8,
                        username.len(),
                    );
                }
                state = 4;
            } else {
                assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
                state = 3;
            }
        } else if state == 5 {
            println!("預ける金額を入力してください。");
            input_line(&mut input);
            let sub_money: u64 = input.parse().unwrap();
            unsafe {
                deposit_ecall(
                    enclave.geteid(),
                    &mut retval,
                    username.as_ptr() as *const u8,
                    username.len(),
                    sub_money,
                );
            }
            state = 3;
        } else if state == 9 {
            println!("取引を終了します。ありがとうございました。");
            break;
        }
    }

    enclave.destroy();
}
