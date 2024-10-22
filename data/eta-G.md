# [1] Optimizing Address Calculation for Burn Addresses in StarkNet Contracts to Reduce Gas Costs

## Summary
The `_commit_account` and `_cache_precompile` functions in StarkNet's Cairo contracts currently use the `compute_starknet_address` method to repeatedly calculate the StarkNet address. Since the address for a constant like `BURN_ADDRESS` remains the same across calls, recalculating it each time introduces inefficiencies and higher gas costs. This is particularly relevant when handling operations like account state commits and caching precompiled account information, where unnecessary address calculations occur.
## Proof of Concept 
The `_commit_account` function in the Starknet.cairo contract is responsible for committing the account state to the StarkNet storage backend. If a **selfdestruct** operation is triggered on an account, the function avoids committing the data and burns any leftover balance. Additionally, the function uses the `compute_starknet_address` function from the account contract to compute the StarkNet address corresponding to `Constants.BURN_ADDRESS` every time the function is invoked. 
[kakarot/src/backend/starknet.cairo:_commit_account-L193](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/backend/starknet.cairo#L193)
```cairo
            // @notice Commit the account to the storage backend at given address
            // @dev Account is deployed here if it doesn't exist already
            // @dev Works on model.Account to make sure only finalized accounts are committed.
            // @dev If the contract received funds after a selfdestruct in its creation, the funds are burnt.
            // @param self The pointer to the Account
            // @param starknet_address A starknet address to commit to
            // @param native_token_address The address of the native token
            // @notice Iterate through the storage dict and update the Starknet storage
            func _commit_account{
                syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, state: model.State*
            }(self: model.Account*, native_token_address) {
                alloc_locals;

                let is_precompile = PrecompilesHelpers.is_precompile(self.address.evm);
                if (is_precompile != FALSE) {
                    return ();
                }

                let starknet_account_exists = Account.is_registered(self.address.evm);
                let starknet_address = self.address.starknet;
                // Case new Account
                if (starknet_account_exists == 0) {
                    // Deploy account
                    Starknet.deploy(self.address.evm);
                    tempvar syscall_ptr = syscall_ptr;
                    tempvar pedersen_ptr = pedersen_ptr;
                    tempvar range_check_ptr = range_check_ptr;
                } else {
                    tempvar syscall_ptr = syscall_ptr;
                    tempvar pedersen_ptr = pedersen_ptr;
                    tempvar range_check_ptr = range_check_ptr;
                }

                // @dev: EIP-6780 - If selfdestruct on an account created, dont commit data
                // and burn any leftover balance.
                let is_created_selfdestructed = self.created * self.selfdestruct;
                if (is_created_selfdestructed != 0) {
@audit=>            let starknet_address = Account.compute_starknet_address(Constants.BURN_ADDRESS);
                    tempvar burn_address = new model.Address(
            starknet=starknet_address, evm=Constants.BURN_ADDRESS
                    );
                    let transfer = model.Transfer(self.address, burn_address, [self.balance]);
                    State.add_transfer(transfer);
                    return ();
                }

                let has_code_or_nonce = Account.has_code_or_nonce(self);
                if (has_code_or_nonce == FALSE) {
                    // Nothing to commit
                    return ();
                }

                // Set nonce
                IAccount.set_nonce(starknet_address, self.nonce);
                // Save storages
                Internals._save_storage(starknet_address, self.storage_start, self.storage);

                // Update bytecode and jumpdests if required (newly created account)
                if (self.created != FALSE) {
                    IAccount.write_bytecode(starknet_address, self.code_len, self.code);
                    Internals._save_valid_jumpdests(
                        starknet_address, self.valid_jumpdests_start, self.valid_jumpdests
                    );
                    IAccount.set_code_hash(starknet_address, [self.code_hash]);
                    return ();
                }

                return ();
            }
```

The `compute_starknet_address` function is used to convert an Ethereum (EVM) address into a StarkNet address. In the case of a **constant address** like `Constants.BURN_ADDRESS`, the calculated StarkNet address will likely be the same each time it's computed, which introduces inefficiencies and could lead to **increased gas consumption**.
[kakarot/src/kakarot/account.cairo:compute_starknet_address-L515-L560](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/account.cairo#L515C1-L560C6)
```cairo
    // @dev As contract addresses are deterministic we can know what will be the address of a starknet contract from its input EVM address
    // @dev Adapted code from: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/core/os/contract_address/contract_address.cairo
    // @param evm_address The EVM address to transform to a starknet address
    // @return contract_address The Starknet Account Contract address (not necessarily deployed)
    func compute_starknet_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        evm_address: felt
    ) -> felt {
        alloc_locals;
        let (kakarot_address: felt) = get_contract_address();
        let (
            uninitialized_account_class_hash: felt
        ) = Kakarot_uninitialized_account_class_hash.read();
        let (constructor_calldata_len, constructor_calldata) = get_constructor_calldata(
            evm_address
        );
        let (hash_state_ptr) = hash_init();
        let (hash_state_ptr) = hash_update_single{hash_ptr=pedersen_ptr}(
            hash_state_ptr=hash_state_ptr, item=Constants.CONTRACT_ADDRESS_PREFIX
        );
        // hash deployer
        let (hash_state_ptr) = hash_update_single{hash_ptr=pedersen_ptr}(
            hash_state_ptr=hash_state_ptr, item=kakarot_address
        );
        // hash salt
        let (hash_state_ptr) = hash_update_single{hash_ptr=pedersen_ptr}(
            hash_state_ptr=hash_state_ptr, item=evm_address
        );
        // hash class hash
        let (hash_state_ptr) = hash_update_single{hash_ptr=pedersen_ptr}(
            hash_state_ptr=hash_state_ptr, item=uninitialized_account_class_hash
        );
        // hash constructor arguments
        let (hash_state_ptr) = hash_update_with_hashchain{hash_ptr=pedersen_ptr}(
            hash_state_ptr=hash_state_ptr,
            data_ptr=constructor_calldata,
            data_length=constructor_calldata_len,
        );
        let (contract_address_before_modulo) = hash_finalize{hash_ptr=pedersen_ptr}(
            hash_state_ptr=hash_state_ptr
        );
        let (contract_address) = normalize_address{range_check_ptr=range_check_ptr}(
            addr=contract_address_before_modulo
        );

        return contract_address;
    }
```

**Optimization Suggestion:**
- If feasible, replace the `compute_starknet_address` call with `get_starknet_address` in the `_commit_account` function. 
- The `get_starknet_address` method can provide a more efficient alternative, particularly for registered addresses. It will result in **lower gas costs** when the address has already been stored, while maintaining similar efficiency for unregistered addresses.
[kakarot/src/kakarot/account.cairo:get_starknet_address-L570](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/account.cairo#L570C1-L570C48)
```cairo
           // @notice Returns the corresponding Starknet address for a given EVM address.
            // @dev Returns the registered address if there is one, otherwise returns the deterministic address got when Kakarot deploys an account.
            // @param evm_address The EVM address to transform to a starknet address
            // @return starknet_address The Starknet Account Contract address
            func get_starknet_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
                evm_address: felt
            ) -> felt {
                let registered_starknet_address = get_registered_starknet_address(evm_address);
@audit=>        if (registered_starknet_address != 0) {
                    return registered_starknet_address;
                }

                let computed_starknet_address = compute_starknet_address(evm_address);
                return computed_starknet_address;
            }
```

Similarly, the `_cache_precompile` function in the `state.cairo` contract is designed to cache precompiled account information in the system state. Its primary purpose is to **create an initial state for precompiled accounts** and cache this information to allow for quick access without recalculating or fetching from an external source. The function also repeatedly calls `compute_starknet_address` to compute the StarkNet address for `Constants.BURN_ADDRESS`.
[Breadcrumbskakarot/src/kakarot/state.cairo:_cache_precompile-L467](https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/state.cairo#L467)
```cairo
            // @notice Cache a precompiled account in the state.
            // @param evm_address The EVM address of the precompiled account.
            func _cache_precompile{
                syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, accounts_ptr: DictAccess*
            }(evm_address: felt) {
                alloc_locals;
@audit=>        let starknet_address = Account.compute_starknet_address(evm_address);
                tempvar address = new model.Address(starknet=starknet_address, evm=evm_address);
                let balance = Account.fetch_balance(address);
                tempvar balance_ptr = new Uint256(balance.low, balance.high);
                let (bytecode) = alloc();
                // empty code hash see https://eips.ethereum.org/EIPS/eip-1052
                tempvar code_hash_ptr = new Uint256(
                    Constants.EMPTY_CODE_HASH_LOW, Constants.EMPTY_CODE_HASH_HIGH
                );
                let account = Account.init(
                    address=address,
                    code_len=0,
                    code=bytecode,
                    code_hash=code_hash_ptr,
                    nonce=0,
                    balance=balance_ptr,
                );
                dict_write{dict_ptr=accounts_ptr}(key=address.evm, new_value=cast(account, felt));
                return ();
            }

```

## Recommended Mitigation Steps
Replace the `compute_starknet_address` calls in both the `_commit_account` and `_cache_precompile` functions with `get_starknet_address`. This change would:
- **Reduce gas consumption** by avoiding redundant address computations for constant addresses.
- Ensure **more efficient state handling** for precompiled and burn addresses.