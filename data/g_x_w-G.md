## Incorrect Gas Fee Calculation due to `State.is_account_alive`

### Summary
The `State.is_account_alive` function is intended to determine if a Starknet address corresponds to a live account. However, it is being used to calculate gas fees, leading to incorrect charges in certain scenarios. Specifically, the current logic does not account for externally owned accounts (EOAs) created through `kakarot.deploy_externally_owned_account`, which results in an unnecessary gas fee of 25,000 being charged during transactions involving such accounts.

### Affected Code
The following snippets demonstrate the incorrect usage of `State.is_account_alive` in two functions:

1. **`exec_call`**:

    ```
    let is_account_alive = State.is_account_alive(to);
    tempvar is_value_non_zero = is_not_zero(value.low) + is_not_zero(value.high);
    tempvar is_value_non_zero = is_not_zero(is_value_non_zero);
    let create_gas_cost = (1 - is_account_alive) * is_value_non_zero * Gas.NEW_ACCOUNT;
    let transfer_gas_cost = is_value_non_zero * Gas.CALL_VALUE;

    tempvar extra_gas = access_gas_cost + create_gas_cost + transfer_gas_cost;
    let evm = EVM.charge_gas(evm, extra_gas + memory_expansion.cost);
    ```

2. **`exec_selfdestruct`**:

    ```
    let is_recipient_alive = State.is_account_alive(recipient);
    let self_account = State.get_account(evm.message.address.evm);
    tempvar is_self_balance_zero = Helpers.is_zero(self_account.balance.low) * Helpers.is_zero(self_account.balance.high);
    tempvar gas_selfdestruct_new_account = (1 - is_recipient_alive) * (1 - is_self_balance_zero) * Gas.SELF_DESTRUCT_NEW_ACCOUNT;

    let evm = EVM.charge_gas(evm, access_gas_cost + gas_selfdestruct_new_account);
    ```

### Issue Description
The gas fee for creating a new account (`NEW_ACCOUNT` or `SELF_DESTRUCT_NEW_ACCOUNT`, both set at 25,000 gas) should only be charged when a new contract account is deployed. However, the current implementation of `State.is_account_alive` does not take into account the creation of EOAs through `kakarot.deploy_externally_owned_account`, where the Starknet address corresponding to the EVM address is already deployed as an externally owned account (EOA).

This causes unnecessary gas fees to be charged for operations involving EOAs, as `State.is_account_alive` checks only if:

```
if (nonce + code_len + balance.low + balance.high != 0) {
    return TRUE;
}
```

For accounts created with `deploy_externally_owned_account`, both the nonce, code length, and balance are zero, meaning they are falsely classified as new accounts, even though they are not.

### Impact
This bug results in unnecessary gas costs being applied when a user interacts with an externally owned account that was previously deployed using `kakarot.deploy_externally_owned_account`. Specifically, users are overcharged 25,000 gas for operations such as function calls or self-destruct operations, despite the fact that no new contract deployment is required. This can lead to a significant increase in transaction costs, especially for frequent contract interactions, negatively impacting the user experience and contract efficiency.

### Recommendation
To resolve this issue, the logic in `State.is_account_alive` should be updated to accurately reflect the state of EOAs created via `deploy_externally_owned_account`. The condition for determining whether an account is alive should be adjusted to account for such EOAs, ensuring that gas is not unnecessarily charged for already deployed accounts.
