
# QA Report for **Kakarot**

# QA-01 Classic `PUSH0` seems to be broken on Kakarot as it doesn't increase the program counter

## Proof of Concept

Where as the `PushOperations#exec_push()` works for the opcodes of `PUSH1 - PUSH32`, it's broken for `PUSH0` .

To go into more details, the check for the length is done against the opcode number which is stored as `0x5f`, this is because the value of the `PUSH1` opcode is at `0x60`, which then means that after the deduction we know the correct amount of length to increment the program counter by `EVM.increment_program_counter(evm, len)` which in the case of `PUSH1` would be `1` and `PUSH2` would be `2` since it's at `0x61` and so on up until `PUSH32`.
Take a look at the `exec_push` function in the `PushOperations` namespace:

```cairo
func exec_push{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    bitwise_ptr: BitwiseBuiltin*,
    stack: model.Stack*,
    memory: model.Memory*,
    state: model.State*,
}(evm: model.EVM*) -> model.EVM* {
    alloc_locals;

    let opcode_number = [evm.message.bytecode + evm.program_counter];
    let i = opcode_number - 0x5f;

    // Copy code slice
    let pc = evm.program_counter + 1;
    let out_of_bounds = is_nn(pc + i - evm.message.bytecode_len);
    local len = (1 - out_of_bounds) * i + out_of_bounds * (evm.message.bytecode_len - pc);

    let stack_element = Helpers.bytes_to_uint256(len, evm.message.bytecode + pc);
    Stack.push_uint256(stack_element);

    let evm = EVM.increment_program_counter(evm, len);//@audit program counter is wrongly increased during `PUSH0`

    return evm;
}
```

Evidently, this function is used to sort out the push operation opcodes on the.

Now per the specification of EIP 3855: https://eips.ethereum.org/EIPS/eip-3855 that covers the `PUSH0` opcode, we can see the [below](https://raw.githubusercontent.com/ethereum/EIPs/9f3b9e92df5a5ab441ef5946846bdcc2f18315ce/EIPS/eip-3855.md):

> ## Specification
>
> The instruction `PUSH0` is introduced at `0x5f`. It has no immediate data, pops no items from the stack, and places a single item with the value 0 onto the stack. The cost of this instruction is 2 gas (aka `base`).

Now from other section of the EIP we can see how this logic is implemented, cause the previous/stale use of `PUSH1 0` costs more gas, i.e higher than the base gas, see the _Motivation_ for more info.

> ## Motivation

> Many instructions expect offsets as inputs, which in a number of cases are zero. A good example is the return data parameters of `CALLs`, which are set to zeroes in case the contract prefers using `RETURNDATA*`. This is only one example, but there are many other reasons why a contract would need to push a zero value. They can achieve that today by `PUSH1 0`, which costs 3 gas at runtime, and is encoded as two bytes which means `2 * 200` gas deployment cost.

In Kakarot's case however the implementation of `PUSH0` wouldn't work this is because when the `opcode_number = 0x5f`, `i` becomes `0`, since it's calculated as `opcode_number - 0x5f` which leads to the following:

- As hinted earlier on `i` is `0` cause we have `opcode_number = 0x5f` and `0x5f - 0x5f`.
- `len` is calculated as `0`.
- `Helpers.bytes_to_uint256(0, ...)` is called, which also zeroes out, see the implementation at [utils.cairo#L121-L145](https://github.com/kkrt-labs/kakarot/blob/6f4005e4ba65604e547a413fad646b197942e2b0/cairo_zero/utils/utils.cairo#L121-L145) and how it defaults to `res = Uint256(0,0)` which is correct in our case.
- `0` gets correctly pushed on the stack via `Stack.push_uint256(stack_element)`
- All the above are the correct functionality and as expected, **Issue however is that we then attempt to inrease the program counter by `0` considering we have our `len` as `0`** via `EVM.increment_program_counter(evm, len)`

As already shown earlier in the report, we understand how after pushin `0` on the stack we should instead increase the counter by `1` just as is done if `PUSH1 0` was to be done.

## Impact

Inequivalence with the EVM _(which is crucial for this project)_, i,e in this case we can conclude the push operation `PUSH0` is not supported _(incompletely supported)_ and instead leads to unexpected behavior or transaction failure as if it's part of stack with multiple opcodes, the tx gets stuck on the `PUSH0` since it doesn't increment the counter correctly to the next step.

## Recommended Mitigation Steps

Add an explicit check for `PUSH0` and still increase the counter by `1` in such scenarios.

```diff
func exec_push{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    bitwise_ptr: BitwiseBuiltin*,
    stack: model.Stack*,
    memory: model.Memory*,
    state: model.State*,
}(evm: model.EVM*) -> model.EVM* {
    alloc_locals;

    let opcode_number = [evm.message.bytecode + evm.program_counter];

+   if (opcode_number == 0x5f) {  // PUSH0
+       Stack.push_uint256(Uint256(0, 0));
+        let evm = EVM.increment_program_counter(evm, 1);
+        return evm;
+   }
    let i = opcode_number - 0x5f;

    // Copy code slice
    let pc = evm.program_counter + 1;
    let out_of_bounds = is_nn(pc + i - evm.message.bytecode_len);
    local len = (1 - out_of_bounds) * i + out_of_bounds * (evm.message.bytecode_len - pc);

    let stack_element = Helpers.bytes_to_uint256(len, evm.message.bytecode + pc);
    Stack.push_uint256(stack_element);

    return evm;
}
```

# Borderline L/M issues below

> NB: Some of these issues have been attached as H/M subs with more detailed explanation where deemed fit.

# QA-02 Incorrect Address Aliasing Applied to EOAs

## Proof of Concept

Kakarot inherits the address aliasing logic from Optimism as hinted in [`AddressAliasHelper.sol`](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/solidity_contracts/src/L1L2Messaging/AddressAliasHelper.sol):

[Content remains largely the same]

Issue however is that Kakarot applies this aliasing logic not only on contracts but even EOAs, see https://github.com/kkrt-labs/kakarot/blob/b8f5f2a20bd733cc8885c010291885e1df7dc50e/solidity_contracts/src/L1L2Messaging/L1KakarotMessaging.sol#L8:

```solidity
    function sendMessageToL2(address to, uint248 value, bytes calldata data) external payable {
        uint256 totalLength = data.length + 4;
        uint256[] memory convertedData = new uint256[](totalLength);
        convertedData[0] = uint256(uint160(AddressAliasHelper.applyL1ToL2Alias(msg.sender)));
        // ... [rest of the function]
    }
```

## Impact

Misapplication of address aliasing to EOAs instead of only smart contracts can lead to unexpected behavior in cross-chain transactions. This may result in incorrect access control implementations and failed transactions.

## Recommended Mitigation Steps

Implement a check using `msg.sender != tx.origin` to ensure address aliasing is only applied to smart contracts.

# QA-03 Lack of Message Cancellation Functionality in Cross-Chain Communication

## Proof of Concept

[Content remains largely the same, including all hyperlinks]

## Impact

The inability to cancel cross-chain messages creates a potential risk for users, especially in scenarios where the destination chain experiences issues or the user needs to reverse a transaction.

## Recommended Mitigation Steps

Implement a cancellation mechanism with appropriate access controls to allow users to cancel pending cross-chain messages.

# QA-04 EIP-2930 Transaction Decoding Failure

## Proof of Concept

Take a look at https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/utils/eth_transaction.cairo#L101-L157

```cairo
    func decode_2930{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
        tx_data_len: felt, tx_data: felt*
    ) -> model.EthTransaction* {
        // ... [beginning of the function]
        assert items_len = 8;
        // ... [rest of the function]
    }
```

[Rest of the content remains largely the same, including all hyperlinks]

## Impact

The current implementation fails to correctly decode EIP-2930 transactions, breaking compatibility with this transaction type and potentially causing issues for users attempting to use access lists.

## Recommended Mitigation Steps

Modify the `decode_2930()` function to expect 11 items in the transaction data, aligning with the EIP-2930 specification.

# QA-05 Inaccurate Results from Saturated Subtraction Function

## Proof of Concept

Take a look at [utils.cairo#L40](https://github.com/kkrt-labs/kakarot/blob/b8f5f2a20bd733cc8885c010291885e1df7dc50e/cairo_zero/utils/utils.cairo#L40)

```cairo
    func saturated_sub{range_check_ptr}(a, b) -> felt {
        let res = a - b;
        let is_res_nn = is_nn(res);
        if (is_res_nn != FALSE) {
            return res;
        }
        return 0;
    }
```

[Rest of the content remains largely the same, including all hyperlinks]

## Impact

The `saturated_sub` function may incorrectly return 0 for some positive results, leading to potential calculation errors and unexpected behavior in dependent operations.

## Recommended Mitigation Steps

Implement a direct comparison between `a` and `b` before performing the subtraction to ensure accurate results for all input values.

# QA-06 SHA-256 Precompile Gas Pricing Misalignment with EIP-7667

## Proof of Concept

From the [readMe](https://github.com/code-423n4/2024-09-kakarot?tab=readme-ov-file#overview), we understand Kakarot's goal of providing a provable EVM built on the Cairo ZK-VM and integrated with Starknet, emphasizing the importance of accurate gas pricing.

EIP-7667 proposes a significant increase in gas costs for hash function opcodes and precompiles, including the SHA256 precompile used in the current Cairo implementation.

The current SHA-256 precompile implementation uses this gas pricing model (https://github.com/kkrt-labs/kakarot-ssj/blob/d4a7873d6f071813165ca7c7adb2f029287d14ca/crates/evm/src/precompiles/sha256.cairo#L8-L9):

```rust
const BASE_COST: u64 = 60;
const COST_PER_WORD: u64 = 12;
// ..snip
let data_word_size = ((input.len() + 31) / 32).into();
let gas = BASE_COST + data_word_size * COST_PER_WORD;
```

However, [EIP-7667](https://eips.ethereum.org/EIPS/eip-7667) suggests significantly higher gas costs:

```
Parameter	Previous value	New value
SHA256_BASE_COST	60	300
SHA256_WORD_COST	12	60
```

## Impact

This misalignment leads to:

- Undercharging for SHA-256 operations
- Potential economic imbalances in applications using this precompile
- Possible exploitation of the difference between reported and actual gas costs

## Recommended Mitigation Steps

Implement a dynamic gas cost adjustment mechanism:

```rust
fn exec(mut input: Span<u8>) -> Result<(u64, Span<u8>), EVMError> {
    let (base_cost, word_cost) = get_current_gas_costs();

    let data_word_size = ((input.len() + 31) / 32).into();
    let gas = base_cost + data_word_size * word_cost;

    // ... rest of the function remains the same
}

fn get_current_gas_costs() -> (u64, u64) {
    // Retrieve current gas costs from a configurable source
}
```

This approach allows for flexible updates to gas costs, maintaining alignment with network costs and supporting Kakarot's goal of providing an accurate and efficient EVM implementation.

# QA-07 Incorrect Handling of 0^0 in Power Function

## Proof of Concept

The `pow` function implementation in the `ExponentiationImpl` trait (https://github.com/kkrt-labs/kakarot/blob/b8f5f2a20bd733cc8885c010291885e1df7dc50e/cairo/kakarot-ssj/crates/utils/src/math.cairo#L26-L62) incorrectly handles the case of 0^0:

```rust
impl ExponentiationImpl<
    T,
    +Zero<T>,
    +One<T>,
    +Add<T>,
    +Sub<T>,
    +Mul<T>,
    +Div<T>,
    +BitAnd<T>,
    +PartialEq<T>,
    +Copy<T>,
    +Drop<T>
> of Exponentiation<T> {
    fn pow(self: T, mut exponent: T) -> T {
        let zero = Zero::zero();
        if self.is_zero() {
            return zero;
        }
        // ... rest of the function
    }
}
```

This implementation returns 0 for 0^0, which is mathematically incorrect in most contexts.

## Impact

This can lead to unexpected behavior in calculations, potentially causing errors in financial or scientific computations where precision is crucial.

## Recommended Mitigation Steps

Explicitly handle the 0^0 case:

```rust
fn pow(self: T, exponent: T) -> T {
    let zero = Zero::zero();
    let one = One::one();

    if self.is_zero() {
        if exponent.is_zero() {
            return one; // Define 0^0 as 1
        }
        return zero;
    }

    // ... rest of the function
}
```

Alternatively, return a Result type to emphasize the undefined nature of 0^0:

```rust
fn pow(self: T, exponent: T) -> Result<T, PowerError> {
    if self.is_zero() && exponent.is_zero() {
        return Err(PowerError::UndefinedZeroPower);
    }

    // ... rest of the function
}
```

# QA-08 ECADD/ECMUL Implementation Deviates from Ethereum VM Specification

## Proof of Concept

[EIP-196](https://eips.ethereum.org/EIPS/eip-196) specifies that ECADD/ECMUL precompiles should fail on invalid input and consume all provided gas. Kakarot's implementation doesn't follow this specification.

In Kakarot's implementation (https://github.com/kkrt-labs/kakarot-ssj/blob/d4a7873d6f071813165ca7c7adb2f029287d14ca/crates/evm/src/precompiles/ec_operations/ec_add.cairo#L28-L63):

```cairo
fn exec(input: Span<u8>) -> Result<(u64, Span<u8>), EVMError> {
    let gas = BASE_COST;

    // ... snip

    let (x, y) = match ec_add(x1, y1, x2, y2) {
        Option::Some((x, y)) => { (x, y) },
        Option::None => {
            return Result::Err(EVMError::InvalidParameter('invalid ec_add parameters'));
        },
    };

    // ... rest of the function
}
```

The function returns an error without consuming all gas when given invalid parameters.

## Impact

This deviation from the Ethereum VM specification can lead to inconsistencies in gas consumption and potential vulnerabilities in cross-chain applications expecting standard Ethereum behavior.

## Recommended Mitigation Steps

Modify the implementation to consume all provided gas even when invalid input is detected, aligning with the Ethereum VM specification.

# QA-09 EIP-1559 Transaction Decoding Failure

## Proof of Concept

The `decode_1559` function (https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/utils/eth_transaction.cairo#L164-L222) incorrectly assumes 9 items in the transaction data:

```cairo
func decode_1559{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    tx_data_len: felt, tx_data: felt*
) -> model.EthTransaction* {
    // ... beginning of function

    assert items_len = 9;

    // ... rest of function
}
```

However, [EIP-1559](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md#abstract) specifies 11 items in the transaction data.

## Impact

This implementation fails to correctly decode EIP-1559 transactions, breaking compatibility with fee market transactions.

## Recommended Mitigation Steps

Update the assertion to expect 11 items instead of 9, and adjust the subsequent parsing logic accordingly to handle all fields specified in EIP-1559.

# QA-10 Contract Creation Transactions Fail Due to Incorrect Address Parsing

## Proof of Concept

The `try_parse_destination_from_bytes` function (https://github.com/kkrt-labs/kakarot/blob/6496ee1d18380dae5b069c27b3129d82ae282419/cairo_zero/utils/utils.cairo#L238) incorrectly handles address parsing:

```cairo
func try_parse_destination_from_bytes(bytes_len: felt, bytes: felt*) -> model.Option {
    if (bytes_len != 20) {
        with_attr error_message("Bytes has length {bytes_len}, expected 0 or 20") {
            assert bytes_len = 0;
        }
        let res = model.Option(is_some=0, value=0);
        return res;
    }
    let address = bytes20_to_felt(bytes);
    let res = model.Option(is_some=1, value=address);
    return res;
}
```

This function fails to properly handle contract creation transactions where the destination address should be empty (length 0).

## Impact

Valid contract creation transactions consistently fail due to the incorrect address length check, breaking a fundamental Ethereum transaction type.

## Recommended Mitigation Steps

Modify the check to allow both 0 and 20 byte lengths:

```cairo
if (bytes_len != 20 and bytes_len != 0) {
    with_attr error_message("Bytes has length {bytes_len}, expected 0 or 20") {
        assert false;
    }
}
```

# QA-11 ECRECOVER Precompile Inaccessible Due to Incorrect Routing

## Proof of Concept

In [cairo1_helpers.cairo](https://github.com/kkrt-labs/kakarot-ssj/blob/d4a7873d6f071813165ca7c7adb2f029287d14ca/crates/contracts/src/cairo1_helpers.cairo#L131-L149), the ECRECOVER precompile is not properly routed:

```cairo
fn exec_precompile(
    self: @TContractState, address: felt252, data: Span<u8>
) -> (bool, u64, Span<u8>) {
    let result = match address {
        0 => Result::Err(EVMError::NotImplemented),
        1 => Result::Err(EVMError::NotImplemented),//@audit
        2 => Sha256::exec(data),
        // ... other precompiles
    };
    // ... rest of the function
}
```

## Impact

The ECRECOVER precompile is inaccessible, breaking signature verification functionality crucial for many Ethereum operations.

## Recommended Mitigation Steps

Update the precompile routing:

```diff
use evm::precompiles::EcAdd;
+ use evm::precompiles::EcRecover;

fn exec_precompile(
    self: @TContractState, address: felt252, data: Span<u8>
) -> (bool, u64, Span<u8>) {
    let result = match address {
        0 => Result::Err(EVMError::NotImplemented),
-       1 => Result::Err(EVMError::NotImplemented),
+       1 => EcRecover::exec(data),
        2 => Sha256::exec(data),
        // ... other precompiles
    };
    // ... rest of the function
}
```

# QA-12 Incorrect SELFDESTRUCT Implementation Leads to Fund Loss

## Proof of Concept

The `_commit_account` function (https://github.com/kkrt-labs/kakarot/blob/6496ee1d18380dae5b069c27b3129d82ae282419/cairo_zero/backend/starknet.cairo#L164) incorrectly handles SELFDESTRUCT:

```cairo
func _commit_account{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, state: model.State*
}(self: model.Account*, native_token_address) {
    // ... beginning of function

    let is_created_selfdestructed = self.created * self.selfdestruct;
    if (is_created_selfdestructed != 0) {
        let starknet_address = Account.compute_starknet_address(Constants.BURN_ADDRESS);
        tempvar burn_address = new model.Address(
            starknet=starknet_address, evm=Constants.BURN_ADDRESS
        );
        let transfer = model.Transfer(self.address, burn_address, [self.balance]);
        State.add_transfer(transfer);
        return ();
    }

    // ... rest of function
}
```

This implementation burns funds after SELFDESTRUCT instead of transferring them to the specified target.

## Impact

Users lose funds when using SELFDESTRUCT, contradicting Ethereum's standard behavior and potentially causing significant financial losses.

## Recommended Mitigation Steps

Implement proper fund transfer to the SELFDESTRUCT target:

```cairo
if (is_created_selfdestructed != 0) {
    let target_address = // Retrieve SELFDESTRUCT target
    let transfer = model.Transfer(self.address, target_address, [self.balance]);
    State.add_transfer(transfer);
    return ();
}
```

Ensure the SELFDESTRUCT target is properly tracked and used for fund transfer instead of burning.
