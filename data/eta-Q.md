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

# [02]Bypassing `assert_only_self`: Delegate Call Vulnerability and Reentrancy Risks in accounts/library.cairo Contracts

## Proof of Concept 
The `assert_only_self` function, intended to restrict access to certain functions in Cairo contracts, can be bypassed due to limitations in the `get_caller_address()` behavior. According to the [official Cairo documentation](https://docs.cairo-lang.org/hello_starknet/user_auth.html#), In Cairo, the `get_caller_address()` function returns the address of the contract or account that invoked the current contract. If called directly (not via another contract), it returns 0. If the contract supports **delegate calls**, the function returns the address of the calling contract rather than the one executing the code. This allows an attacker’s contract to bypass the `assert_only_self` check, creating a security loophole.

Additionally, if the contract interacts with external contracts that call back the original contract, `get_caller_address()` will return the external contract’s address, potentially causing the `assert_only_self` check to fail. This could also lead to vulnerabilities, such as **reentrancy attacks**. 

[kakarot/src/kakarot/accounts/library.cairo:assert_only_self-L375-L383](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/accounts/library.cairo#L375C1-L383C6)
```cairo
    // @notice Asserts that the caller is the account itself.
    func assert_only_self{syscall_ptr: felt*}() {
        let (this) = get_contract_address();
        let (caller) = get_caller_address();
        with_attr error_message("Only the account itself can call this function") {
            assert caller = this;
        }
        return ();
    }
```

## Recommended Mitigation Steps
To enhance security, consider using the [OpenZeppelin `assert_only_self` function](https://docs.openzeppelin.com/contracts-cairo/0.12.0/api/account#AccountComponent-assert_only_self) to ensure that only the contract itself can call specific functions. Alternatively, you can add further checks inside `assert_only_self`—for example, not only verifying the caller but also validating the **execution context** using state variables.