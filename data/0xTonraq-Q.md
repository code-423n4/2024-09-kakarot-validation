The `assert_only_self()` function in `src/kakarot/accounts/library.cairo` is unused.

```cairo

func assert_only_self{syscall_ptr: felt*}() {
        let (this) = get_contract_address();
        let (caller) = get_caller_address();
        with_attr error_message("Only the account itself can call this function") {
            assert caller = this;
        }
        return ();
    }

```

