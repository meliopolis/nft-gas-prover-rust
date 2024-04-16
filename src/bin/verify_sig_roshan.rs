use axiom_sdk::{
    axiom::{AxiomAPI, AxiomComputeFn, AxiomComputeInput, AxiomResult},
    cmd::run_cli,
    ethers::{
        types::Address,
        utils::{hex, keccak256},
    },
    halo2_base::{halo2_proofs::plonk::Assigned, AssignedValue},
    subquery::TxField,
    Fr, HiLo,
};
use secp256k1::{ecdsa::RecoveryId, Message, PublicKey};

fn from_hilo_to_bytes(hilo: HiLo<AssignedValue<Fr>>) -> [u8; 32] {
    let mut bytes: [u8; 32] = [0u8; 32];
    bytes[..16].copy_from_slice(&hilo.lo().value().to_bytes()[..16]);
    bytes[16..].copy_from_slice(&hilo.hi().value().to_bytes()[..16]);
    bytes.reverse();
    bytes
}

fn from_bytes_to_hilo(api: &mut AxiomAPI, bytes: [u8; 32]) -> HiLo<AssignedValue<Fr>> {
    let mut cloned_bytes = bytes;
    cloned_bytes.reverse();
    let u64_array_lo: [u64; 4] = [
        u64::from_le_bytes(cloned_bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(cloned_bytes[8..16].try_into().unwrap()),
        u64::MIN,
        u64::MIN,
    ];
    let u64_array_hi: [u64; 4] = [
        u64::from_le_bytes(cloned_bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(cloned_bytes[24..].try_into().unwrap()),
        u64::MIN,
        u64::MIN,
    ];
    let fr_hi = Fr::from_raw(u64_array_hi);
    let fr_lo = Fr::from_raw(u64_array_lo);

    let av_hi = api.ctx().load_witness(fr_hi);
    let av_lo = api.ctx().load_witness(fr_lo);
    HiLo::from_hi_lo([av_hi, av_lo])
}

#[AxiomComputeInput]
pub struct VerifySigInput {
    pub addr: Address,
    pub claimed_block_number: u64,
    pub tx_idx: u64,
}

impl AxiomComputeFn for VerifySigInput {
    fn compute(
        api: &mut AxiomAPI,
        assigned_inputs: VerifySigCircuitInput<AssignedValue<Fr>>,
    ) -> Vec<AxiomResult> {
        // 1. use Axiom to get r s and v for input block number and txn index
        let r = api
            .get_tx(assigned_inputs.claimed_block_number, assigned_inputs.tx_idx)
            .call(TxField::R);
        let s = api
            .get_tx(assigned_inputs.claimed_block_number, assigned_inputs.tx_idx)
            .call(TxField::S);
        let v = api
            .get_tx(assigned_inputs.claimed_block_number, assigned_inputs.tx_idx)
            .call(TxField::V);

        // 2. convert r, s and v to bytes
        let r_bytes: [u8; 32] = from_hilo_to_bytes(r);
        let s_bytes: [u8; 32] = from_hilo_to_bytes(s);
        let mut v_bytes: [u8; 4] = [0u8; 4];
        v_bytes[..4].copy_from_slice(&v.lo().value().to_bytes()[..4]);
        v_bytes.reverse();

        println!("r_bytes: {:?}", hex::encode(r_bytes));
        println!("s_bytes: {:?}", hex::encode(s_bytes));
        println!("v_bytes: {:?}", hex::encode(v_bytes));

        // 2a. let's attempt to turn r back into hilo to verify our conversion code
        let r_hilo = from_bytes_to_hilo(api, r_bytes);
        let s_hilo = from_bytes_to_hilo(api, s_bytes);
        println!("r_hilo_check: {:?}", r_hilo);
        println!("s_hilo_check: {:?}", s_hilo);

        // 3. fetch the transaction data to generate hash
        // TODO: implement this

        // 4. generate hash from transaction data
        // for right now, hard coding a hash
        let hash_string = "0d7085b7555b1180dcbe8f11d3c99ff21a42a3b5a828802d5810b9577eae3661";
        let hash_vec = hex::decode(hash_string).unwrap();
        let hash_bytes: [u8; 32] = hash_vec.clone().try_into().unwrap();

        // 5. use the hash and r, s, v to verify the signature and recover public key
        let message = Message::from_digest_slice(&hash_vec).unwrap();
        println!("message: {:?}", hex::encode(message.as_ref()));

        // 6. Create the signature object from `r` and `s`
        let recovery_id = RecoveryId::from_i32(i32::from_be_bytes(v_bytes)).unwrap();
        let recoverable_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
            &[r_bytes, s_bytes].concat(),
            recovery_id,
        )
        .unwrap();

        let secp = secp256k1::Secp256k1::new();
        let pk: PublicKey = secp.recover_ecdsa(&message, &recoverable_sig).unwrap();
        let pk_uncompressed: [u8; 65] = pk.serialize_uncompressed();
        println!("publicKey: {:?}", hex::encode(pk.serialize()));
        println!("publicKey: {:?}", hex::encode(pk_uncompressed));
        let keccak256_pk: [u8; 32] = keccak256(&pk_uncompressed[1..]);
        println!("keccak256(pk): 0x{}", hex::encode(keccak256_pk));
        println!("address: 0x{}", hex::encode(&keccak256_pk[12..])); // this works!

        // 7. convert message hash to HiLo<AssignedValue<Fr>> to use in the circuit
        let hash_hilo = from_bytes_to_hilo(api, hash_bytes);
        println!("hash_hilo: {:?}", hash_hilo);

        // Check that conversion worked by verifying the reverse with original
        let hash_hilo_bytes: [u8; 32] = from_hilo_to_bytes(hash_hilo);
        assert_eq!(
            hex::encode(&hash_vec),
            hex::encode(hash_hilo_bytes),
            "hash: {:?}, hash_hilo_bytes: {:?}",
            hex::encode(&hash_vec),
            hex::encode(hash_hilo_bytes),
        );

        // 8. Convert public key into (HiLo<AssignedValue<Fr>>, HiLo<AssignedValue<Fr>>) to use in the circuit
        let pk0_bytes: [u8; 32] = pk_uncompressed.to_vec()[1..33].to_vec().try_into().unwrap(); // ignoring first byte
        let pk1_bytes: [u8; 32] = pk_uncompressed.to_vec()[33..65]
            .to_vec()
            .try_into()
            .unwrap();
        println!("pk1: {:?}", hex::encode(pk0_bytes));
        println!("pk2: {:?}", hex::encode(pk1_bytes));
        let pk0_hilo = from_bytes_to_hilo(api, pk0_bytes);
        let pk1_hilo = from_bytes_to_hilo(api, pk1_bytes);
        let pk_hilo = (pk0_hilo, pk1_hilo);
        println!("pk_hilo: {:?}", pk_hilo);

        let ecdsa_verify = api.ecdsa_sig_verify(pk_hilo, r, s, hash_hilo);
        println!("ecdsa_verify: {:?}", ecdsa_verify);

        // Last step: return the confirmed values
        vec![
            assigned_inputs.addr.into(),
            assigned_inputs.claimed_block_number.into(),
            assigned_inputs.tx_idx.into(),
        ]
    }
}

fn main() {
    run_cli::<VerifySigInput>();
}
