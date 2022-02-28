use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn create_sealeddata(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        message: *const u8,
        message_len: usize,
    ) -> sgx_status_t;
    fn ecall_print_vec(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        message: *mut i32,
        message_len: usize,
    ) -> sgx_status_t;
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

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };
    let enclave_eid = enclave.geteid();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let msg = String::from("hello sealed data");

    let result = unsafe {
        create_sealeddata(
            enclave_eid,
            &mut retval,
            msg.as_ptr() as *const u8,
            msg.len(),
        )
    };
    if result != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", result.as_str());
        return;
    }

    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", retval.as_str());
        return;
    }

    // Allocate vector big enough for 4 elements.
    // let size = 5;
    // let mut x: Vec<i32> = Vec::with_capacity(size);
    // let x_ptr = x.as_mut_ptr();
    // let message = String::from("hello, ecall!");
    // let message_ptr = message.as_ptr() as *const u8;
    
    // let mut retval_2 = sgx_status_t::SGX_SUCCESS;

    // unsafe {
    //     for i in 0..size {
    //         *x_ptr.add(i) = i as i32;
    //     }
    //     x.set_len(size);
    //     ecall_print_vec(enclave_eid, &mut retval_2, x_ptr, size);
    // }

    println!("[+] sealeddata success...");
    enclave.destroy();
}