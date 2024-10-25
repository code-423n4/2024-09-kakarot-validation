In the `fetch_or_create` function: https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/account.cairo#L111-L137
the account's codehash is always computed as `EMPTY_CODE_HASH` even though it should be 0 if the account has no code,balance,or nonce. Note that the `extcodehash` opcode is implemented correctly and accounts for these cases. As a result accessing an account's codehash from within Kakarot behaves properly as far as I can tell.

Geth will not charge gas if the nonce overflows (notice how buy_gas is only called at the end of the checks): https://github.com/ethereum/go-ethereum/blob/65e5ca7d8126f7a8c708f8affb64f16c22cc63c0/core/state_transition.go#L284-L300
However Kakarot does: https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/interpreter.cairo#L948-L957
This is probably unhittable in practice anyway

The natspec for the `execute` function is wrong: https://github.com/kkrt-labs/kakarot/blob/7411a5520e8a00be6f5243a50c160e66ad285563/src/kakarot/interpreter.cairo#L800-L819 some of the params are not there 