# [L1] Potential Underflow in packed_tx_data_len - 1 in execute_from_outside

	•	Severity: Low

### Impact
If packed_tx_data_len is 1, subtracting 1 results in zero, which may not be properly handled by Helpers.load_packed_bytes.

### Location
```txt
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/accounts/account_contract.cairo#L95-L149
```
```Cairo
let (tx_data) = Helpers.load_packed_bytes(
    packed_tx_data_len - 1, packed_tx_data + 1, tx_data_len
);
```
### Description
When packed_tx_data_len equals 1, packed_tx_data_len - 1 results in zero. If Helpers.load_packed_bytes does not handle a length of zero correctly, this could lead to unexpected behavior or errors.

### Proof of Concept (PoC)
If packed_tx_data_len is 1, the function call becomes Helpers.load_packed_bytes(0, ...), which may not be intended.

### Recommended Mitigation
Add a check to ensure packed_tx_data_len is greater than 1.
```Cairo
with_attr error_message("packed_tx_data_len must be greater than 1") {
    assert_le(2, packed_tx_data_len);
}
````
	•	Severity Level: Low
	•	Issue Type: Under-constrained computations

# [L2] Missing Data Unpacking Validations in execute_starknet_call

### Impact 
Lack of validations when unpacking data can lead to incorrect execution if the inputs are malformed.

### Location
```txt
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/accounts/account_contract.cairo#L333-L349
```
```Cairo
@external
func execute_starknet_call{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt, function_selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_len: felt, retdata: felt*, success: felt) {
    Ownable.assert_only_owner();
    let (kakarot_address) = Ownable.owner();
    let is_get_starknet_address = Helpers.is_zero(
        GET_STARKNET_ADDRESS_SELECTOR - function_selector
    );
    let is_kakarot = Helpers.is_zero(kakarot_address - to);
    tempvar is_forbidden = is_kakarot * (1 - is_get_starknet_address);
    if (is_forbidden != FALSE) {
        let (error_len, error) = Errors.kakarotReentrancy();
        return (error_len, error, FALSE);
    }
    let (retdata_len, retdata) = call_contract(to, function_selector, calldata_len, calldata);
    return (retdata_len, retdata, TRUE);
}
```

### Description
The execute_starknet_call function lacks validations on calldata_len and calldata. If malformed or inconsistent data is provided, it may lead to unexpected behavior during the call_contract execution.

### Proof of Concept (PoC)
An attacker could provide a calldata_len that does not match the actual length of calldata, potentially causing out-of-bounds reads.

### Recommended Mitigation
Ensure that calldata_len matches the actual length of calldata provided.
```Cairo
// Add appropriate checks or validations as per the contract's context
if (calldata_len != calldata.len) {
   return ()
}
```
	•	Severity Level: Low
	•	Issue Type: Data unpacking

# [L3] Missing Boolean Range Check on authorized Parameter in set_authorized_cairo_precompile_caller

### Impact
The set_authorized_cairo_precompile_caller function accepts an authorized parameter of type felt but does not enforce that it should be either TRUE (1) or FALSE (0). If an unintended value is provided, it may lead to unexpected behavior in authorization logic, potentially causing security issues or logic errors.

### Location
    •    Function: set_authorized_cairo_precompile_caller
    •    File: Kakarot.Cairo

### Line
```txt
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/kakarot.cairo#L234-L239
```
```Cairo
@external
func set_authorized_cairo_precompile_caller{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(evm_address: felt, authorized: felt) {
    Ownable.assert_only_owner();
    return Kakarot.set_authorized_cairo_precompile_caller(evm_address, authorized);
}
```

### Proof of Concept (PoC)
An attacker with ownership privileges could call the function with an unintended authorized value:
```Cairo
// Setting authorized to an unintended value
await kakarot_contract.set_authorized_cairo_precompile_caller(evm_address, 42)
```
This could bypass authorization checks if the underlying logic treats any non-zero value as TRUE.

### Recommended Mitigation Steps
Add a check to ensure that authorized is either TRUE (1) or FALSE (0):
```Cairo
@external
func set_authorized_cairo_precompile_caller{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(evm_address: felt, authorized: felt) {
    Ownable.assert_only_owner();
    assert (authorized == TRUE) or (authorized == FALSE), 'authorized must be TRUE or FALSE';
    return Kakarot.set_authorized_cairo_precompile_caller(evm_address, authorized);
}
```
Alternatively, define the authorized parameter as a boolean type if supported.

# [L4] Missing Address Validation in Functions Accepting Addresses Allows Setting Invalid Addresses

### Impact
Functions like set_coinbase, set_native_token, set_account_contract_class_hash, and others accept address parameters but do not validate that these addresses are valid (e.g., within the correct range for StarkNet addresses). This could allow the owner—or an attacker who gains control over the owner’s account—to set invalid addresses, potentially causing failures in other parts of the system that rely on these addresses.

### Location
    •    Functions: set_coinbase, set_native_token, set_account_contract_class_hash, etc.
    •    File: Kakarot.Cairo
    •    Lines:
```txt
set_coinbase:
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/kakarot.cairo#L140-L143

set_native_token:
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/kakarot.cairo#L103-L108

set_account_contract_class_hash:
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/kakarot/kakarot.cairo#L204-L209
```
### Example of set_coinbase:
```Cairo
@external
func set_coinbase{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(coinbase: felt) {
    Ownable.assert_only_owner();
    return Kakarot.set_coinbase(coinbase);
}
```

### Proof of Concept (PoC)
An attacker could set an invalid address:
```Cairo
// Setting coinbase to an invalid address
await kakarot_contract.set_coinbase(2**251 + 1)
```
This could cause failures when the coinbase address is used in other contract operations.

### Recommended Mitigation Steps
Add checks to validate that the addresses provided are within the valid range for StarkNet addresses (e.g., less than 2**251):
```Cairo
@external
func set_coinbase{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(coinbase: felt) {
    Ownable.assert_only_owner();
    assert coinbase < 2**251, 'Invalid coinbase address';
    return Kakarot.set_coinbase(coinbase);
}
```

# [L5] Data Packing/Unpacking Issue with prev_randao in get_env Function

Severity: Low
Issue Type: Data Packing/Unpacking Issue

### Impact
Incorrect data handling when packing or unpacking the prev_randao variable can lead to unexpected behavior or bugs in the environment setup, potentially affecting any computations or logic that rely on it.

### Location
Starknet.get_env function, lines where prev_randao is reconstructed.
```txt
https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/backend/starknet.cairo#L106-L130
```

### Code Snippet
```Cairo
// From Starknet.get_env
let (prev_randao) = Kakarot_prev_randao.read();

// No idea why this is required - but trying to pass prev_randao directly causes bugs.
let prev_randao = Uint256(low=prev_randao.low, high=prev_randao.high);

return new model.Environment(
    origin=origin,
    gas_price=gas_price,
    chain_id=chain_id,
    prev_randao=prev_randao,
    block_number=block_number,
    block_gas_limit=block_gas_limit,
    block_timestamp=block_timestamp,
    coinbase=coinbase,
    base_fee=base_fee,
);
```

### Description
The prev_randao variable is read and then immediately reconstructed using its low and high components. The comment indicates uncertainty about why this reconstruction is necessary and mentions bugs when passing prev_randao directly. This suggests potential issues with data packing or unpacking, which can lead to incorrect values being used in the Environment structure.

### Proof of Concept
If prev_randao is not properly handled, it may not correctly represent the intended 256-bit value, causing functions that rely on it to behave unexpectedly.

### Recommended Mitigation
Investigate the underlying issue that necessitates reconstructing prev_randao. Ensure that the Kakarot_prev_randao.read() function returns a correctly structured Uint256 and that the Environment constructor accepts it without requiring reconstruction.
```Cairo
// Potential mitigation in Starknet.get_env
let (prev_randao) = Kakarot_prev_randao.read();
return new model.Environment(
    origin=origin,
    gas_price=gas_price,
    chain_id=chain_id,
    prev_randao=prev_randao,  // Pass directly if possible
    block_number=block_number,
    block_gas_limit=block_gas_limit,
    block_timestamp=block_timestamp,
    coinbase=coinbase,
    base_fee=base_fee,
);
```
