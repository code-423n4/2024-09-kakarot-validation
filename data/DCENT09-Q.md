1. Title:No events for critical actions
Explanation:
The library does not emit events for critical state changes (e.g., when a successful call, delegatecall, or staticcall is executed). Events are vital for on-chain transparency and off-chain monitoring.
Impact:
Low to Moderate Impact: Lack of events makes it hard for external observers (e.g., dApps, monitoring systems) to track important contract interactions. This can lead to decreased transparency or delayed response times in case of an issue.
Mitigation:
Emit events for important state-changing or external call interactions. This makes it easier to audit the contract's behavior and catch any potential issues early.
Example event addition:
event CairoCallExecuted(address indexed target, uint256 functionSelector, bytes result);

function callCairo(uint256 contractAddress, uint256 functionSelector, uint256[] memory data)
    internal
    returns (bytes memory)
{
    bytes memory result = _callCairo(contractAddress, functionSelector, data);
    emit CairoCallExecuted(contractAddress, functionSelector, result);
    return result;
}

2. Title:Potential Gas Griefing Attack
Explanation:
The callCairo, delegatecallCairo, and staticcallCairo functions do not impose any gas limits on the external calls. This means a user can pass in excessive data or interact with a contract that consumes a large amount of gas, causing transactions to fail or become prohibitively expensive.
Impact:
Moderate Impact: A gas griefing attack can make functions unusable, causing denial of service (DoS). If a malicious external contract intentionally uses excessive gas, it can force a contract into failure.
Mitigation:
Set a reasonable gas limit for external calls to prevent excessive gas consumption.
Example gas limit:
(bool success, bytes memory result) = contractAddress.call{gas: gasleft() / 2}(callData);
require(success, "CairoLib: External call failed");

3. Title: Overuse of abi.encodeWithSignature
Explanation:
Using abi.encodeWithSignature("call_contract(uint256,uint256,uint256[])", ...) introduces unnecessary complexity, as the ABI encoding can be done more efficiently with abi.encode. The current implementation can also be error-prone, particularly if the contract being called has a different function signature or data layout than expected.
Impact:
Low to Moderate Impact: It increases gas costs and introduces the possibility of bugs if the signature or parameters mismatch. The impact of this depends on how frequently these calls are made.
Mitigation:
Switch to abi.encode for cleaner and more efficient encoding.
bytes memory callData = abi.encode(contractAddress, functionSelector, data);
