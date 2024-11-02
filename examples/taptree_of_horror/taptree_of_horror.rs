use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, Psbt, PublicKey, Sequence, TxIn, TxOut};
use helper_fns::{produce_grim_hash, produce_kelly_hash, produce_key_pairs};
use miniscript::descriptor::DescriptorSecretKey;
use miniscript::policy::Concrete;
use miniscript::psbt::PsbtExt;
use miniscript::{Descriptor, DescriptorPublicKey};
mod helper_fns;

pub const KEYS_PER_PERSONA: usize = 9;

fn main() {
    let secp: &secp256k1::Secp256k1<secp256k1::All> = &secp256k1::Secp256k1::new();

    // ====== 1. Setup Hardcoded Values for all of the Personas ======

    // Define derivation paths that will be used
    let normal_path = "86'/1'/0'/0";
    let unhardened_path = "86/1/0/0";
    let weird_path = "69'/420'/999999999'/8008135'";

    // Hard coded regtest tprvs that will be used.
    let internal = format!("tprv8ZgxMBicQKsPfBJTWzMTQfRzcE3HCNKg6TUBpGBfigcFbqTXNBw6SuGPqBpD6D9pjLLASwq8bE7oZXCtMFPDKRizLy14xNqw4uz1zwrfo2c/{normal_path}/*");
    let alice = format!("tprv8ZgxMBicQKsPeZjVFDhZR5wjfCvFNev9qKGPDPC77p5cAEgEMUCR8Cecaf8pYfY7NTz8QcjVnP8uR8NedPz8o7iG7qWgnFMyQy9BAhMVZgb/{normal_path}/*");
    let bob = format!("tprv8ZgxMBicQKsPeHy2kPPVzYpbUqwTVBjSthMJUcGyqUiXk8eZTQ6xrJKEmdX8NYJKLLGCHGjuByqz2ahJXp52E8zCUV7njziJzwN7V7zfrKZ/{normal_path}/*");
    let charlie = format!("tprv8ZgxMBicQKsPdYaiWLUQCprj7Ej9Ka5GEq6giWHgTnbJvdLWnSuYnsF5sonVh6iy2HzvfkfxRDAmWEXNo3SJWTHCXM6XuxVZvqxtEyjdC29/{normal_path}/*");
    let dave = format!("tprv8ZgxMBicQKsPfCRUoMSWthoE8aJKr7De5YkxS1y55PuiSoi5ACyYUbas8Kv4vVtDzhKnBgY7cVSuogg2QLqtFcSZVv4ZTeBEzkzSnF9cSUT/{weird_path}/*");
    let eve = format!("tprv8ZgxMBicQKsPdYD5umCPZeh6tMqKfQATctqJbycgJ5N1rrJ15cHMgxds5iYENHZHmkMiXccAqUFx2k3ZNwU9qxPMjrKvTbCtgLFxk7mjMWD/{normal_path}/*");
    let frank = format!("tprv8ZgxMBicQKsPemyPyxqZ85T1UjpToCbLQ7uSn4JpbtwMBCodjvrLbgjBZeGgT4tMHdHCqyieDwCNzE7RrtRMVCQjPKQbGJzrg5vfn4eT7og/{normal_path}/*");
    let heather = format!("tprv8ZgxMBicQKsPefp99xLkwnQbU9LEEb8v4Aig3o4hwnjbaYotixkbJv3Ssmog68ptHij2LgExefNU96DYJKtFbDazTr1jm48twYhQLG775qw/{normal_path}/*");
    let ian = format!("tprv8ZgxMBicQKsPfGsuwfAdg3xPP452wreLk7ZEgusb8zdMqh1fyKGKnzFbxyxeHY3qhg8ESDRp5F6RgWiQGcvkmLyERcMys5V8DuT4gvxMDmS/{unhardened_path}/*");
    let judy = format!("tprv8ZgxMBicQKsPcz4VcN87e2e9k1LHDBLLajbVSAKAedpm1qakjtRT5xrdnmsQARWAfwg3REr6sNd5YHeWuWkHVvyey3rYmq9xYorMvwY3XAB/{normal_path}/*");
    let liam = format!("tprv8ZgxMBicQKsPcycCJ2v7B1utZrhWJNdQTBm7m9eR6iX1D9a9YvjbCNeT6dTEdMh4JziVCHD4YHQ7AXkZNMLfaBVf3CCiVWQLxwdU2SnrPcT/{normal_path}/*");
    let s_backup_1 = format!("tprv8ZgxMBicQKsPetPYYt5GUtNmQPChghNDBLbgJXz3cTZopeDrxHMendLpujaBHMPX3dXLZcv2NkgAvxMeuf1jWBU3iYxdeJAhktdeM9cKcYF/{normal_path}/*");
    let x_backup_2 = format!("tprv8ZgxMBicQKsPdf55kYg8pVPrUaW3VLZyt8XwxwrvSPkpskxDah1mAWypsTTZJeomWPrGf4e5RyT4zVzENHrwAsXxJP2EPYbfrYLRVFC1rLb/{normal_path}/*");

    // define DescriptorSecretKeys
    let internal_desc_secret = DescriptorSecretKey::from_str(&internal).unwrap();
    let a_descriptor_desc_secret = DescriptorSecretKey::from_str(&alice).unwrap();
    let b_descriptor_desc_secret = DescriptorSecretKey::from_str(&bob).unwrap();
    let c_descriptor_desc_secret = DescriptorSecretKey::from_str(&charlie).unwrap();
    let d_descriptor_desc_secret = DescriptorSecretKey::from_str(&dave).unwrap();
    let e_descriptor_desc_secret = DescriptorSecretKey::from_str(&eve).unwrap();
    let f_descriptor_desc_secret = DescriptorSecretKey::from_str(&frank).unwrap();
    let h_descriptor_desc_secret = DescriptorSecretKey::from_str(&heather).unwrap();
    let i_descriptor_desc_secret = DescriptorSecretKey::from_str(&ian).unwrap();
    let j_descriptor_desc_secret = DescriptorSecretKey::from_str(&judy).unwrap();
    let l_descriptor_desc_secret = DescriptorSecretKey::from_str(&liam).unwrap();
    let s_descriptor_desc_secret = DescriptorSecretKey::from_str(&s_backup_1).unwrap();
    let x_descriptor_desc_secret = DescriptorSecretKey::from_str(&x_backup_2).unwrap();
    let grim = produce_grim_hash("sovereignty through knowledge");
    let kelly = produce_kelly_hash("the ultimate pre-preimage");

    // ====== 2. Derive Keys, Preimages, Hashes, and Timelocks for Policy and Signing ======

    let internal_xpub: miniscript::DescriptorPublicKey =
        internal_desc_secret.to_public(secp).unwrap();

    // example of how defining the internal xpriv that can be used for signing.
    // let internal_xpriv: DescriptorXKey<bitcoin::bip32::Xpriv> = match internal_desc_secret {
    //     miniscript::descriptor::DescriptorSecretKey::XPrv(x) => Some(x.clone()),
    //     _ => None,
    // }
    // .unwrap();

    let (a_pks, a_prvs) = produce_key_pairs(a_descriptor_desc_secret, secp, normal_path, "alice");
    let (b_pks, b_prvs) = produce_key_pairs(b_descriptor_desc_secret, secp, normal_path, "bob");
    let (c_pks, c_prvs) = produce_key_pairs(c_descriptor_desc_secret, secp, normal_path, "charlie");
    let (d_pks, d_prvs) = produce_key_pairs(d_descriptor_desc_secret, secp, weird_path, "dave");
    let (e_pks, e_prvs) = produce_key_pairs(e_descriptor_desc_secret, secp, normal_path, "eve");
    let (f_pks, f_prvs) = produce_key_pairs(f_descriptor_desc_secret, secp, normal_path, "frank");
    let (h_pks, h_prvs) = produce_key_pairs(h_descriptor_desc_secret, secp, normal_path, "heather");
    let (i_pks, i_prvs) = produce_key_pairs(i_descriptor_desc_secret, secp, unhardened_path, "ian");
    let (j_pks, j_prvs) = produce_key_pairs(j_descriptor_desc_secret, secp, normal_path, "judy");
    let (l_pks, l_prvs) = produce_key_pairs(l_descriptor_desc_secret, secp, normal_path, "liam");
    let (s_pks, _s_prvs) =
        produce_key_pairs(s_descriptor_desc_secret, secp, normal_path, "s_backup1");
    let (x_pks, _x_prvs) =
        produce_key_pairs(x_descriptor_desc_secret, secp, normal_path, "x_backup2");

    // For this example we are grabbing the 9 keys for each persona
    let [a0, a1, a2, a3, a4, a5, a6, a7, a8]: [PublicKey; KEYS_PER_PERSONA] =
        a_pks[..].try_into().unwrap();
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8]: [PublicKey; KEYS_PER_PERSONA] =
        b_pks[..].try_into().unwrap();
    let [c0, c1, c2, c3, c4, c5, c6, c7, c8]: [PublicKey; KEYS_PER_PERSONA] =
        c_pks[..].try_into().unwrap();
    let [d0, d1, d2, d3, d4, d5, d6, d7, d8]: [PublicKey; KEYS_PER_PERSONA] =
        d_pks[..].try_into().unwrap();
    let [e0, e1, e2, e3, e4, e5, e6, e7, e8]: [PublicKey; KEYS_PER_PERSONA] =
        e_pks[..].try_into().unwrap();
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8]: [PublicKey; KEYS_PER_PERSONA] =
        f_pks[..].try_into().unwrap();
    let [h0, h1, h2, h3, h4, h5, h6, h7, h8]: [PublicKey; KEYS_PER_PERSONA] =
        h_pks[..].try_into().unwrap();
    let [i0, i1, i2, i3, i4, i5, i6, i7, i8]: [PublicKey; KEYS_PER_PERSONA] =
        i_pks[..].try_into().unwrap();
    let [j0, j1, j2, j3, j4, j5, j6, j7, j8]: [PublicKey; KEYS_PER_PERSONA] =
        j_pks[..].try_into().unwrap();
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8]: [PublicKey; KEYS_PER_PERSONA] =
        l_pks[..].try_into().unwrap();
    let [_s0, _s1, s2, _s3, s4, s5, _s6, s7, s8]: [PublicKey; KEYS_PER_PERSONA] =
        s_pks[..].try_into().unwrap();
    let [_x0, _x1, x2, _x3, x4, x5, x6, _x7, x8]: [PublicKey; KEYS_PER_PERSONA] =
        x_pks[..].try_into().unwrap();

    // Hashes that will also be used in the policy.
    let g = grim.1;
    let k = kelly.1;
    // Absolute timelocks that were used at TABConf 6, The event took place Oct 23-26 and more spending paths for the puzzle became available during the conference.
    let oct_23_morning: u32 = 1729692000; // Oct 23, 10:00 AM EST
    let oct_24_evening: u32 = 1729819800; // Oct 24, 09:30 PM EST
    let oct_25_afternoon: u32 = 1729877400; // Oct 25, 01:30 PM EST
    let oct_26_morning: u32 = 1729942200; // Oct 26, 07:30 AM EST

    // ====== 3. Create Taptree Policy and Descriptor ======

    let pol_str = format!(
        "or(
            pk({internal_xpub}),
            or(
                and(
                    thresh(10, pk({a0}), pk({b0}), pk({c0}), pk({d0}), pk({e0}), pk({f0}), pk({h0}), pk({i0}), pk({j0}), pk({l0})),
                    thresh(3, sha256({k}), ripemd160({g}), after({oct_23_morning}))
                ),
                or(
                    or(
                        and(
                            thresh(8, pk({a1}), pk({b1}), pk({c1}), pk({e1}), pk({f1}), pk({h1}), pk({i1}), pk({j1}), pk({l1})),
                            thresh(3, pk({d1}), sha256({k}), after({oct_24_evening}))
                        ),
                        and(
                            thresh(4, pk({a2}), pk({b2}), pk({c2}), pk({e2}), pk({f2}), pk({h2}), pk({i2}), pk({l2})),
                            and(
                                thresh(4, pk({d2}), pk({j2}), ripemd160({g}), after({oct_24_evening})),
                                or(pk({s2}), pk({x2}))
                            )
                        )
                    ),
                    or(
                        or(
                            or(
                                and(
                                    thresh(6, pk({a3}), pk({b3}), pk({c3}), pk({e3}), pk({f3}), pk({h3}), pk({i3}), pk({l3})),
                                    thresh(4, pk({d3}), pk({j3}),  sha256({k}), after({oct_25_afternoon}))
                                ),
                                thresh(14, pk({a8}), pk({b8}), pk({c8}), pk({d8}), pk({e8}), pk({f8}), pk({h8}), pk({i8}), pk({j8}), pk({l8}), pk({s8}), pk({x8}), sha256({k}), ripemd160({g}))
                            ),
                            or(
                                and(
                                    thresh(9, pk({a4}), pk({b4}), pk({c4}), pk({d4}), pk({e4}), pk({f4}), pk({h4}), pk({i4}),  pk({j4}), pk({l4}), pk({s4}), pk({x4})),
                                    thresh(2, sha256({k}), after({oct_26_morning}))
                                ),
                                and(
                                    thresh(10, pk({a5}), pk({b5}), pk({c5}), pk({d5}), pk({e5}), pk({f5}), pk({h5}), pk({i5}),  pk({j5}), pk({l5}), pk({s5}), pk({x5})),
                                    after({oct_26_morning})
                                )
                            )
                        ),
                        or(
                            and(
                                thresh(4, pk({a6}), pk({b6}), pk({c6}), pk({e6}), pk({f6}), pk({h6}), pk({i6}), pk({l6})),
                                thresh(5, pk({d6}), pk({x6}), pk({j6}), ripemd160({g}), after({oct_25_afternoon}))
                            ),
                            and(
                                thresh(4, pk({a7}), pk({b7}), pk({c7}), pk({e7}), pk({f7}), pk({h7}), pk({i7}), pk({l7})),
                                thresh(5, pk({d7}), pk({s7}), pk({j7}), ripemd160({g}), after({oct_25_afternoon}))
                            )
                        )
                    )
                )
            )

        )"
    )
    .replace(&[' ', '\n', '\t'][..], "");

    // make sure policy doesn't have any issues
    let pol = Concrete::<DescriptorPublicKey>::from_str(&pol_str).unwrap();
    let policy_desc: Descriptor<DescriptorPublicKey> = pol.compile_tr(None).unwrap();

    // Now, using this public descriptor create the script address
    let derived_descriptor = policy_desc.at_derivation_index(0).unwrap();
    let _script_address = derived_descriptor.address(Network::Regtest).unwrap();
    println!("the receiving address of this script is: {}", _script_address);
    println!("\ndescriptor is: {}\n", policy_desc);

    // We assert internal key is the one used in the descriptor
    match &policy_desc {
        Descriptor::Tr(tr) => {
            // println!("internal: {}, eve: {}", tr.internal_key(), eve_xpub);
            assert!(tr.internal_key() == &internal_xpub);
        }
        _ => panic!("internal spending path is not correct"),
    }

    // ====== 4. Construct an Unsigned Transaction from the Tapscript ======

    let secp: &secp256k1::Secp256k1<secp256k1::All> = &secp256k1::Secp256k1::new();

    let tx_in = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: "8888888899999999aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff"
                .parse()
                .unwrap(),
            vout: 0,
        },
        sequence: Sequence(0),
        //        sequence: Sequence(40),
        ..Default::default()
    };

    let prev_amount = Amount::from_sat(100_000_000);
    let witness_utxo =
        TxOut { value: prev_amount, script_pubkey: derived_descriptor.clone().script_pubkey() };

    let destination_address =
        Address::from_str("bcrt1p2tl8zasepqe3j6m7hx4tdmqzndddr5wa9ugglpdzgenjwv42rkws66dk5a")
            .unwrap();
    let destination_output: TxOut = TxOut {
        value: bitcoin::Amount::from_sat(99_999_000),
        script_pubkey: destination_address.assume_checked().script_pubkey(),
    };

    let time = oct_23_morning;

    let unsigned_tx = bitcoin::Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_time(time).unwrap(),
        input: vec![tx_in],
        output: vec![destination_output],
    };

    let unsigned_tx_test_string = serialize(&unsigned_tx).to_hex_string(Case::Lower);
    assert!(unsigned_tx_test_string == "0200000001ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d60011967");

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(witness_utxo);

    // Tell Psbt about the descriptor so it can sign with it
    psbt.update_input_with_descriptor(0, &derived_descriptor)
        .unwrap();

    // ====== 5. Sign and Create a Spending Transaction ======

    // this is how you would sign for an internal key spend
    //let _res = psbt.sign(&intneral_xpriv.xkey, secp).unwrap();

    // how you would sign using the leaf that uses index 0 keys
    let _res = psbt.sign(&a_prvs[0], secp).unwrap();
    let _res = psbt.sign(&b_prvs[0], secp).unwrap();
    let _res = psbt.sign(&c_prvs[0], secp).unwrap();
    let _res = psbt.sign(&d_prvs[0], secp).unwrap();
    let _res = psbt.sign(&e_prvs[0], secp).unwrap();
    let _res = psbt.sign(&f_prvs[0], secp).unwrap();
    let _res = psbt.sign(&h_prvs[0], secp).unwrap();
    let _res = psbt.sign(&i_prvs[0], secp).unwrap();
    let _res = psbt.sign(&j_prvs[0], secp).unwrap();
    let _res = psbt.sign(&l_prvs[0], secp).unwrap();

    psbt.inputs[0]
        .sha256_preimages
        .insert(kelly.1, kelly.0.to_byte_array().to_vec());

    psbt.inputs[0]
        .ripemd160_preimages
        .insert(grim.1, grim.0.to_byte_array().to_vec());

    // Finalize PSBT now that we have all the required signatures and hash preimages.
    psbt.finalize_mut(secp).unwrap();

    // Now extract the tx
    let signed_tx = psbt.extract_tx().unwrap();
    let raw_tx = bitcoin::consensus::encode::serialize(&signed_tx).to_hex_string(Case::Lower);

    assert!(raw_tx == "02000000000101ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d0e209250ecce1169d94cf17baaecddcef779ff1b0d07d347d24afcd5b2231f95a500209562ef4e826d891eaa72f2cee753b80a3f7f6b5aed07b850227e83546fa6185740a5da084901627205e860d6530ff5ff580fc3841b779ad8535ffd7b466664aa0280c218aa05a1054c73b1f717b6c5badf70e71e5091b4b34e25ec3584243fd0604032a0bad48af9b3263d331ba2c789a931af81755c67dfefab28f8e40658545e6659eeb93d2c501ac79914ca82f4dbdcd669d34c7de73b4c243400926cffeb42b640015f5b58eb820676382521bb38b9d0c16d40c6a1b710242232d3d8276145aee859667d3caf9b72acecbfa3be33ce7afb9bda70b19451c58550bb1076125463c240ba0ba063d92ef71a35a1bdbd41b165d71825d6b5d9555781a3a6c35aba5864c82c4e53a7656458dc8bd586a6de749b6ab59cbb5ec4e2264a185ef7b79db3ea9c408176c65f6486f5c9a7d466fe86dfed7d55f8fc480b5843414696842f1efc689e74fce36a0b318535ef86864d8f83ac4bb60085c2b45c0547b9657def51b52b8e40b5f95b03c77b685314848a292d05bf350cdad506bcb2601b634779e956235aef3bade98a812f046d47060fbf9965ac0ef016e6ef09540c1c7d5b2fe447192cbd405ea9e1a58685ef958db8aa529d3fbfcc1182e252a35715bf9b2c35a30c73e718a65e8a8c0141eaac72af71a1dd7f19c53aaead75ae5b963a4eee5d1228c389844094a38c8574e6089c33d2c37d6f889adb671ef09a188e91cf032e97a3e25e9636901096e1cc92d17fbf4c581e5a1915de53f807f3198f4a2b829fc3a4479f6bb54017e68b70fd9e5c94c6f99abf284f5da42365a2e5fd4f0971bf5cb68aea3408c0d05ace043c15e70958c73f7455db3a22e3e5fb0240749a9dc52aa66a554fb06b40c478230871c12b60bc7cae151e411aa779780a8e6a7afd57aa763185809259fc7853f65e712d1ef178d4750f66e1b6db3cae7efcec5308b815b39fe8498f404afd9c0120fe88003d0bcb15d1628edff84046255758baf205d42ce460b6fb4595b983f2ecad20eecd6dba68fd0ec5d4baa0052db8084cb15a55503b78cfee5ef31c35cd98d846ad20529c1e24d86bf35b35133a81bf1e8c21759f3a83cfb38f18eae1d5b8292ff4bead2083835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06aad204aeb360d05ad743b838ad27c56b78f08668aeba77f2f1fc439ac80f970e57328ad2062c4d094ce7a28414102bacccb06947053e07e4da53ad96e5724565f09436dfcad20f6e5c74176d69d44a97220a694237d8e719fae4a029942aadb28a9b491b40e31ad20dc7ea580c6887971614260d91069c4d398cc80ecc6cbb4ab59099e110ad3bb8bad2059fa3dfd7286d59f9b3853fb0cdd13c4760508f672435be40057b9e02eb937bdad20aa90f13a1c98abc5620d3f379d20b8c28ddf8f46772a0d0af6b7deb7bf3a1ee1ad82012088a8202db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca418882012088a6148d60757ec290d055be92da400cff617b0423cb14880460011967b141c1259b7a61aa66c551a6cd35ccc35e9e011ecbbddbbb673acba71e2e4cc11e8883326f8afc8b0ef3f1cc0428893a40e48b9419807a4fd8f8673b62840ef216d5f660011967");
}
