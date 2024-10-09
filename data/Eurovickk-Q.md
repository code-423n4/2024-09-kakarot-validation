

# dict.cairo

## 1)Unchecked External Function Calls

Functions like ***dict_write***, ***dict_squash***, and ***dict_new*** are

invoked without any error handling mechanisms to check the success of these
 
operations.  

In ***default_dict_copy***, we have the following external function calls

>let (squashed_start, squashed_end) = dict_squash(start, end);
let (local new_start) = default_dict_new(default_value);
dict_write{dict_ptr=new_ptr}(key=key, new_value=new_value);


If any of these function calls fail internally, the contract will proceed  

without knowing that the operation failed, which could lead to incorrect   

dictionary states or data corruption.  

For example, if dict_squash fails to squash the dictionary properly, subsequent   

operations could act on an incorrect or incomplete dictionary.  

You should check the success of these external calls.

>let (squashed_start, squashed_end) = dict_squash(start, end);
assert squashed_start != INVALID;  // Ensure the function did not fail  
let (local new_start) = default_dict_new(default_value);  
assert new_start != INVALID;
dict_write{dict_ptr=new_ptr}(key=key, new_value=new_value);
assert dict_ptr != INVALID;

## 2)Infinite Loops

>tempvar keys = keys_start;
tempvar len = keys_len;
tempvar dict = dict_start;

>loop:
    let keys = cast([ap - 3], felt*);
    let len = [ap - 2];
    let dict = cast([ap - 1], DictAccess*);
    assert [keys] = dict.key;
    tempvar keys = keys + 1;
    tempvar len = len - 1;
    tempvar dict = dict + DictAccess.SIZE;
    jmp loop if len != 0;

Loop Termination: The loop terminates when ***len == 0***. However, if len is 

incorrectly initialized or len doesn't decrement correctly within the loop, the 

condition ***jmp loop if len != 0*** may never become false, leading to an 

infinite loop.

Initialization of len: The variable len is initialized as follows

***let (local keys_len, _) = unsigned_div_rem(dict_len, DictAccess.SIZE);***

This divides the total length of the dictionary (dict_len) by the size of a 

DictAccess entry to determine the number of keys. If dict_len is miscalculated 

or becomes corrupted, keys_len may be incorrect, potentially causing the loop 

to never terminate.

The same structure is used in dict_values

If len is initialized incorrectly (for example, if dict_len is not correctly 

calculated or unsigned_div_rem returns a wrong result), the loop will never 

exit.

Similarly, if the len variable is not decremented properly within the loop, the 

termination condition (len == 0) will never be met, resulting in an infinite 

loop.

Ensure Proper Initialization: Always validate that len is initialized correctly

***assert keys_len > 0;***  // Ensure len is a valid positive number




# array.cairo


## 1)Unchecked Memory Access in reverse

If an attacker passes a value for arr_len that exceeds the allocated memory for 

arr or dst, the function could attempt to read or write outside the bounds of 

memory, causing memory corruption. This could be exploited to overwrite 

important contract state or cause a denial of service (DoS).

No Memory Bound Check, Cairo allows direct pointer arithmetic on memory ***(dst 

+ i - 1 and arr + arr_len - i)***, but there is no guarantee that dst and arr 

point to valid memory regions for the entire range of i.

If the memory location accessed is outside the bounds of the allocated memory, 

the function could end up reading or writing to memory locations it shouldn't. 

This can cause memory corruption, crashes, or unexpected behavior.

Large arr_len Input, if an attacker passes a large value for arr_len that 

exceeds the allocated memory for either arr or dst, the function would attempt 

to access memory outside the valid bounds of these arrays.

Let’s assume that ***arr_len = 100*** but the memory for arr only has space for 

50 elements.

***assert [dst + i - 1] = [arr + arr_len - i];***  // Problematic if arr_len > memory bounds

For i = 100, the function tries to access [arr + 100 - 100] = [arr + 0], which 

is valid. But when i = 51, it attempts to access [arr + 100 - 51] = [arr + 49], 

which is out of bounds because the array only has space for 50 elements.

# stop_and_math_operations.cairo

## 1)Unchecked Arithmetic in MULMOD

The MULMOD function performs modular multiplication but does not properly 

handle cases where the modulus ***(popped[2]) is zero***, which could result in 

division by zero errors or unintended behavior.

PoC: If popped[2] (the modulus) is zero, the division by zero could occur in 

this block.

>MULMOD:
    let range_check_ptr = [ap - 2];
    let popped = cast([ap - 1], Uint256*);
    
    tempvar mod_is_not_zero = popped[2].low + popped[2].high;
    jmp mulmod_not_zero if mod_is_not_zero != 0;

    tempvar bitwise_ptr = cast([fp - 7], BitwiseBuiltin*);
    tempvar range_check_ptr = range_check_ptr;
    tempvar result = Uint256(0, 0);  // This is an unsafe default for zero >modulus
    jmp end;

Add an explicit check for division by zero and handle it safely.

## 2)Gas Undercharging in EXP

In the ***EXP*** code, the gas charge for exponentiation is calculated based on 

the number of bytes in the exponent. If the exponent is large but the base is 

zero, the operation should still consume gas proportional to the size of the 

exponent. However, the current implementation might not accurately charge for 

this operation if it doesn’t properly account for edge cases where the base is 

zero.

PoC:  If the ***base is zero*** but the exponent is large, this would result in undercharging for gas.

>EXP:
    let range_check_ptr = [ap - 2];
    let popped = cast([ap - 1], Uint256*);
    let exponent = popped[1];

    // Gas
    local bytes_used: felt;
    if (exponent.high == 0) {
        let bytes_used_low = Helpers.bytes_used_128(exponent.low);
        assert bytes_used = bytes_used_low;
        tempvar range_check_ptr = range_check_ptr;
    } else {
        let bytes_used_high = Helpers.bytes_used_128(exponent.high);
        assert bytes_used = bytes_used_high + 16;
        tempvar range_check_ptr = range_check_ptr;
    }


Modify the gas charging logic to ensure that gas is properly charged regardless 

of the base's value.

>EXP:
    let range_check_ptr = [ap - 2];
    let popped = cast([ap - 1], Uint256*);
    let base = popped[0];
    let exponent = popped[1];

    // Gas
    local bytes_used: felt;
    if (exponent.high == 0) {
        let bytes_used_low = Helpers.bytes_used_128(exponent.low);
        assert bytes_used = bytes_used_low;
    } else {
        let bytes_used_high = Helpers.bytes_used_128(exponent.high);
        assert bytes_used = bytes_used_high + 16;
    }

    // Properly charge gas even when base is zero
    let evm = EVM.charge_gas(evm, Gas.EXPONENTIATION_PER_BYTE * bytes_used);
    if (evm.reverted != FALSE) {
        return evm;
    }
    
    // Continue with exponentiation logic
    let result = uint256_fast_exp(base, exponent);
    Stack.push_uint256(result);
    return evm;



