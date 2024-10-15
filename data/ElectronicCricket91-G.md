## Precompiled Contracts Waste Compute On Easy to Pre-Compute `OutOfGas` Errors

### Impact

This applies to all of the following precompiled operations:
- `ecMul`
- `ecAdd`
- `blake2f`
- `modexp`
- `sha2-256`
- `ripemd-160`

This impacts all of the files implementing the precompiles specified above, a core area of Kakarot:
- `kakarot-ssj`: https://github.com/kkrt-labs/kakarot-ssj/tree/main/crates/evm/src/precompiles
- `kakarot`: https://github.com/kkrt-labs/kakarot/tree/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/precompiles

These operations can easily save a significant amount of gas / execution cost on the existing kakarot implementations on the CairoVM, when an `EVMError::OutOfGas` occurs.

### Details

On precompiled contracts, there are many cases where the precompiled contract / operation is a fixed cost, or easily computable given the input data / input lengths.

This can be massively improved for performance across precompiled contract functions, to ensure that the gas is computed at the start of the precompile call (which it already is in most cases), and then proceeding, or returning early if the current context does not have the gas available. This approach avoids wasting network compute on precompiled operations which would clearly run out of gas.

In addition, this check already happens *after* the precompile call, so does not add any overhead that wouldn't already occur.

For example, `kakarot-ssj`'s `ecAdd` implementation:

```rust
const BASE_COST: u64 = 150;
const U256_BYTES_LEN: usize = 32;
pub impl EcAdd of Precompile {
    #[inline(always)]
    fn address() -> EthAddress {
        0x6.try_into().unwrap()
    }

    fn exec(input: Span<u8>) -> Result<(u64, Span<u8>), EVMError> {
        let gas = BASE_COST; // <-- We already know here the total fixed cost of the operation!

        // Pad the input to 128 bytes to avoid out-of-bounds accesses
        let mut input = input.pad_right_with_zeroes(128);

        let x1_bytes = *(input.multi_pop_front::<32>().unwrap());
        let x1: u256 = load_word(U256_BYTES_LEN, x1_bytes.unbox().span());

        let y1_bytes = *(input.multi_pop_front::<32>().unwrap());
        let y1: u256 = load_word(U256_BYTES_LEN, y1_bytes.unbox().span());

        let x2_bytes = *(input.multi_pop_front::<32>().unwrap());
        let x2: u256 = load_word(U256_BYTES_LEN, x2_bytes.unbox().span());

        let y2_bytes = *(input.multi_pop_front::<32>().unwrap());
        let y2: u256 = load_word(U256_BYTES_LEN, y2_bytes.unbox().span());

        let (x, y) = match ec_add(x1, y1, x2, y2) {
            Option::Some((x, y)) => { (x, y) },
            Option::None => {
                return Result::Err(EVMError::InvalidParameter('invalid ec_add parameters'));
            },
        };

        let mut result_bytes = array![];
        // Append x to the result bytes.
        let x_bytes = x.to_be_bytes_padded();
        result_bytes.append_span(x_bytes);
        // Append y to the result bytes.
        let y_bytes = y.to_be_bytes_padded();
        result_bytes.append_span(y_bytes);

        return Result::Ok((gas, result_bytes.span()));
    }
}
```

As can be seen, in the first line of `EcAdd::exec(...)` the total gas consumption is pre-determined. This function is called in the `precompiles.cairo` file:

```rust
// precompiles.cairo

// ...

fn exec_precompile(ref vm: VM) -> Result<(), EVMError> {
    // ...
    0x06 => { EcAdd::exec(input)? },
    // ...
    vm.charge_gas(gas)?; // <--- Would revert here if OutOfGas!
    // ...
}
```

### Mitigation / Fix / Improvement

At the point of the VM executing the precompile call, the code has access to the `vm` and therefore the remaining gas in the context. Therefore passing the gas left into the `EcAdd::exec(...)` function would be one way to solve this, by reverting with `EVMError::OutOfGas` at the start of the precompile, instead of computing the full result of the precompile.

Again, using the example of `EcAdd.cairo`:

```rust
const BASE_COST: u64 = 150;
const U256_BYTES_LEN: usize = 32;
pub impl EcAdd of Precompile {
    #[inline(always)]
    fn address() -> EthAddress {
        0x6.try_into().unwrap()
    }

    fn exec(input: Span<u8>, gas_left: u64) -> Result<(u64, Span<u8>), EVMError> {
        let gas = BASE_COST;
        if (gas > gas_left) {
            return Result::Err(EVMError::OutOfGas);
        }
        // <--- Now we avoided ALL unnecessary precompile compute!
        // ... rest of function
    }
}
```

This approach has now reduced all wasted circuit compute and other logic, which would have reverted once the VM checks for the gas left in the context.

This also could specifically be carried out in the same way on the files mentioned. The following links relevant files that could benefit from this optimization, and the line number at which an early return could occur (similar to the `EcAdd.cairo` highlighted above):

##### kakarot-ssj

- `EcAdd.cairo`: https://github.com/kkrt-labs/kakarot-ssj/blob/9203b9c29c5e049d556cafdb3554929f7c719143/crates/evm/src/precompiles/ec_operations/ec_add.cairo#L28
- `EcMul.cairo`: https://github.com/kkrt-labs/kakarot-ssj/blob/9203b9c29c5e049d556cafdb3554929f7c719143/crates/evm/src/precompiles/ec_operations/ec_mul.cairo#L20 
- `EcRecover.cairo`: https://github.com/kkrt-labs/kakarot-ssj/blob/9203b9c29c5e049d556cafdb3554929f7c719143/crates/evm/src/precompiles/ec_recover.cairo#L22
- `ExpMod.cairo`: https://github.com/kkrt-labs/kakarot-ssj/blob/9203b9c29c5e049d556cafdb3554929f7c719143/crates/evm/src/precompiles/modexp.cairo#L88
- `sha256.cairo`: https://github.com/kkrt-labs/kakarot-ssj/blob/9203b9c29c5e049d556cafdb3554929f7c719143/crates/evm/src/precompiles/sha256.cairo#L20
- `blake2f.cairo`: https://github.com/kkrt-labs/kakarot-ssj/blob/9203b9c29c5e049d556cafdb3554929f7c719143/crates/evm/src/precompiles/blake2f.cairo#L37

##### kakarot

- `EcRecover.cairo`: https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/precompiles/ec_recover.cairo#L48
- `blake2f.cairo`: https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/precompiles/blake2f.cairo#L61
- `ripemd160.cairo`: https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/precompiles/ripemd160.cairo#L80 (NOTE: This call should be moved to the start of the function)
- `sha256.cairo`: https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/precompiles/sha256.cairo#L63 (NOTE: This call should be moved to the start of the function)

These changes would mark a noticeable underlying improvement on `OutOfGas` errors in most of the precompile implementations, and therefore reduce underlying CairoVM gas & hardware usage as a result.