## [L-1] Redundant Assertions in `decode_legacy_tx`, `decode_2930`, and `decode_1559`
The `assert_nn` statements ensure the byte length of certain fields does not exceed 31 bytes. However, this check might be redundant if the helper functions (`bytes_to_felt`, etc.) already perform validation.

https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/utils/eth_transaction.cairo#L187-L199

## Impact:
Redundant assertions increase `gas` costs without adding security or functionality.

## Proof of Concept:
These assertions do not provide any additional protection if validation is already handled within helper functions.

## Recommended Mitigation:
Remove redundant assertions if validation exists within helper functions.

## code
```solidity
assert_nn(31 - items[0].data_len);

assert_nn(31 - items[1].data_len);

assert_nn(31 - items[2].data_len);
```