#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

extern crate alloc;

use alloc::string::ToString;
use core::alloc::Layout;
use core::panic::PanicInfo;
use core::str::FromStr;

use alloc_cortex_m::CortexMHeap;
use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

// this is the allocator the application will use
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 256; // 256 KB

#[entry]
fn main() -> ! {
    hprintln!("heap size {}", HEAP_SIZE).unwrap();

    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    // begin miniscript test
    let descriptor = "sh(wsh(or_d(\
        c:pk_k(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),\
        c:pk_k(0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352)\
    )))";
    hprintln!("descriptor {}", descriptor).unwrap();
    let desc =
        miniscript::Descriptor::<miniscript::bitcoin::PublicKey>::from_str(descriptor).unwrap();

    // Derive the P2SH address
    let p2sh_addr = desc
        .address(miniscript::bitcoin::Network::Bitcoin)
        .unwrap()
        .to_string();
    hprintln!("p2sh address {}", p2sh_addr).unwrap();
    assert_eq!(p2sh_addr, "3CJxbQBfWAe1ZkKiGQNEYrioV73ZwvBWns");

    // Check whether the descriptor is safe
    // This checks whether all spend paths are accessible in bitcoin network.
    // It maybe possible that some of the spend require more than 100 elements in Wsh scripts
    // Or they contain a combination of timelock and heightlock.
    assert!(desc.sanity_check().is_ok());

    // Estimate the satisfaction cost
    assert_eq!(desc.max_weight_to_satisfy().unwrap(), 288);
    // end miniscript test

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    hprintln!("alloc error").unwrap();
    debug::exit(debug::EXIT_FAILURE);
    asm::bkpt();

    loop {}
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    hprintln!("panic {:?}", info.message()).unwrap();
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}
