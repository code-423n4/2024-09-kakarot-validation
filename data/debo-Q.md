## Uninitialized Memory Access
## https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/utils/bytes.cairo
**Severity**: Low  
**Issue Type**: Uninitialized Storage Pointer

### Impact

Allocated memory using `alloc()` may contain undefined or residual data. Using this memory without proper initialization can lead to unpredictable behavior or security vulnerabilities.

### Location

- **`felt_to_ascii`**: Allocation of `ascii` without initialization.
- **`felt_to_bytes_little`**: Allocation of `bytes` without initialization.
- **`felt_to_bytes`**: Allocation of `bytes` without initialization.
- **Other functions**: Similar patterns in `felt_to_bytes20`, `felt_to_bytes32`, etc.

### Proof of Concept (PoC)

In `felt_to_ascii`:

```cairo
func felt_to_ascii{range_check_ptr}(dst: felt*, n: felt) -> felt {
    alloc_locals;
    let (local ascii: felt*) = alloc();  // Memory allocated but not initialized
    // Rest of the function...
}
```

If `ascii` is used before being fully assigned, it may contain garbage values.

### Mitigation

Initialize allocated memory immediately after allocation:

- **Use `memset`**: Set the allocated memory to zero or a known value.
- **Ensure Complete Assignment**: Before using the memory, ensure all elements are assigned.

### Code Fix

```cairo
func felt_to_ascii{range_check_ptr}(dst: felt*, n: felt) -> felt {
    alloc_locals;
    let (local ascii: felt*) = alloc();
    memset(ascii, 0, MAX_ASCII_LENGTH);  // Initialize memory
    // Rest of the function...
}
```
---

## Potential Integer Overflow in Calculations
## https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/utils/bytes.cairo

**Severity**: Low  
**Issue Type**: Arithmetic Issues

### Impact

Calculations involving large integers might overflow without proper checks, leading to incorrect results or vulnerabilities.

### Location

- **`unsigned_div_rem`**: Usage without ensuring operands are within safe ranges.
- **`split_int`**: Splitting large integers without overflow checks.

### Proof of Concept (PoC)

In `felt_to_bytes_little`:

```cairo
tempvar value = (value - byte) / base;
```

If `value` is less than `byte`, this subtraction can underflow.

### Mitigation
- **Add Assertions**: Ensure values are within expected ranges before operations.

### Code Fix

```cairo
with_attr error_message("Underflow detected") {
    assert_le_felt(byte, value);
}
tempvar value = (value - byte) / base;
```
---

## Missing Error Handling for Division by Zero
## https://github.com/kkrt-labs/kakarot/blob/697100af34444b3931c18596cec56c454caf28ed/src/utils/bytes.cairo

**Severity**: Informational  
**Issue Type**: Error Handling

### Impact

Functions performing division may not handle cases where the divisor is zero, potentially causing runtime errors.

### Location

- **`unsigned_div_rem`**: Division operations without zero checks.
- **`split_int`**: May divide by zero if not properly handled.

### Proof of Concept (PoC)

If `base` is set to zero:

```cairo
let base = 0;
let (n, chunk) = unsigned_div_rem(n, base);  // Division by zero error
```

### Mitigation

Ensure divisors are never zero by adding assertions:

```cairo
with_attr error_message("Division by zero") {
    assert_not_zero(base);
}
```
---

---