# [01] Missing `get_authorized_cairo_precompile_caller` Function Poses Risks in Kakarot and Library Contracts
## Proof of Concept
The kakaro.cairo and library.cairo contracts lack the get_authorized_cairo_precompile_caller function to obtain the EVM address that is authorized to call the Cairo precompiled contract.
The absence of a `get_authorized_cairo_precompile_caller` function in the `kakarot.cairo` and `library.cairo` contracts could lead to several potential vulnerabilities. This function is crucial for retrieving authorized EVM addresses that are allowed to call Cairo precompile contracts. Without it, there may be issues such as a lack of transparency in tracking authorized addresses, access control loopholes, difficulties in debugging or monitoring system interactions, and an increased risk of misconfiguration. 
[kakarot/src/kakarot/kakarot.cairo:set_authorized_cairo_precompile_caller-L230-L239](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/kakarot.cairo#L230C1-L239C2)
```cairo
// @notice Sets the authorization of an EVM address to call Cairo Precompiles
// @param evm_address The EVM address
// @param authorized Whether the EVM address is authorized or not
@external
func set_authorized_cairo_precompile_caller{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(evm_address: felt, authorized: felt) {
    Ownable.assert_only_owner();
    return Kakarot.set_authorized_cairo_precompile_caller(evm_address, authorized);
}

```
[kakarot/src/kakarot/library.cairo:set_authorized_cairo_precompile_caller-L288-L296](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/library.cairo#L288C1-L296C6)
```cairo
    // @notice Sets the authorization of an EVM address to call Cairo Precompiles
    // @param evm_address The EVM address
    // @param authorized Whether the EVM address is authorized or not
    func set_authorized_cairo_precompile_caller{
        syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
    }(evm_address: felt, authorized: felt) {
        Kakarot_authorized_cairo_precompiles_callers.write(evm_address, authorized);
        return ();
    }

```

## Recommended Mitigation Steps
To address these concerns, it would be beneficial to implement a `get_authorized_cairo_precompile_caller` function. This function would allow querying whether specific EVM addresses are authorized to call Cairo precompiles. Implementing such a function would increase transparency, security, and ease of system management.

