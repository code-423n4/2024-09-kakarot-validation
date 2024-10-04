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

### [L2] Missing Data Unpacking Validations in execute_starknet_call

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