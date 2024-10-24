## 1. Carry bit not checked when transferring funds
In order to transfer native currency, the network calls the `add_transfer` function which adds a transfer to the transfer array which will be executed by the state machine. However in that function when the transfer amount is being added to the recipient's balance the Cairo code doesn't check the carry bit which is used for checking for overflows. In the current implementation it's highly unlikely that a balance of a user can ever overflow however at a later point a possible change can make an overflow possible by lowering type size or by creating a system account which holds the max value of a uint256 as its balance in which case, if native currency is transferred to it, it will inadvertently overflow and make the balance a number close to 0 without reverting the transaction.  
https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/state.cairo#L388-L390
```cairo
let (local recipient_balance_new, carry) = uint256_add(
    [recipient.balance], transfer.amount
);
```

## 2. Call data copied and not used
When the Kakarot chain needs to run a precompile it is being done by calling the `external_precompile()` function in the `src/kakarot/precompiles/precompiles.cairo`. In that function the precompile input is being copied to the calldata variable however that variable is never used, this creates the following two issues:
1. The additional memcpy would need to be proved thus making the computation more expensive than it needs to be
2. More gas is being used than needed
https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/precompiles/precompiles.cairo#L230-L255
```cairo
func external_precompile{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    bitwise_ptr: BitwiseBuiltin*,
}(evm_address: felt, input_len: felt, input: felt*) -> (
    output_len: felt, output: felt*, gas_used: felt, reverted: felt
) {
    alloc_locals;
    let (implementation) = Kakarot_cairo1_helpers_class_hash.read();
    let (calldata: felt*) = alloc();
    assert [calldata] = evm_address;
    assert [calldata + 1] = input_len;
    memcpy(calldata + 2, input, input_len);
    let (
        success, gas, return_data_len, return_data
    ) = ICairo1Helpers.library_call_exec_precompile(
        class_hash=implementation, address=evm_address, data_len=input_len, data=input
    );
    if (success != FALSE) {
        return (return_data_len, return_data, gas, 0);
    }
    // Precompiles can only revert with exceptions. Thus if the execution failed, it's an error EXCEPTIONAL_HALT.
    return (return_data_len, return_data, 0, Errors.EXCEPTIONAL_HALT);
}
```

## 3. Missing chainid data length check
The cairo code while decoding several transaction types, checks the length of chainid as can be seen in the following functions:
https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/utils/eth_transaction.cairo#L101-L157
https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/utils/eth_transaction.cairo#L164-L222
however when decoding a legacy transaction the chainid length check is missing which creates inconsistency in the codebase which can later lead to issues
https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/utils/eth_transaction.cairo#L63-L78
```cairo
// pre eip-155 txs have 6 fields, post eip-155 txs have 9 fields
if (items_len == 6) {
    tempvar is_some = 0;
    tempvar chain_id = 0;
} else {
    assert items_len = 9;
    assert items[6].is_list = FALSE;
    assert items[7].is_list = FALSE;
    assert items[8].is_list = FALSE;
    let chain_id = Helpers.bytes_to_felt(items[6].data_len, items[6].data);

    tempvar is_some = 1;
    tempvar chain_id = chain_id;
}
let is_some = [ap - 2];
let chain_id = [ap - 1];
```