# ERC4626 Vault Security Primer v13.7

## Overview
This primer consolidates critical security patterns and vulnerabilities discovered across multiple vault implementations, including ERC4626 vaults, yield-generating vaults, vault-like protocols, auto-redemption mechanisms, weighted pool implementations, cross-chain vault systems, multi-vault architectures, AMM-integrated vault systems, CDP vault implementations, position action patterns, fee distribution mechanisms, funding rate arbitrage systems, collateralized lending vaults, and stablecoin protocols. Use this as a reference when auditing new vault protocols to ensure comprehensive vulnerability detection.

**Latest Update**: Added pattern #366 msg.value Balance Inflation in Gate Checks.

## Critical Vulnerability Patterns

### 1. Non-Standard Token Support Issues
**Pattern**: Vaults assuming standard ERC20 behavior without accounting for fee-on-transfer, rebasing, or other non-standard tokens.

**Vulnerable Code Example**:
```solidity
// VULNERABLE: Assumes amount transferred equals amount received
token.safeTransferFrom(msg.sender, address(this), amount);
deposits.push(Deposit(msg.sender, amount, tokenAddress)); // Wrong for FOT tokens
```

**Secure Implementation**:
```solidity
uint256 balanceBefore = token.balanceOf(address(this));
token.safeTransferFrom(msg.sender, address(this), amount);
uint256 actualAmount = token.balanceOf(address(this)) - balanceBefore;
deposits.push(Deposit(msg.sender, actualAmount, tokenAddress));
```

**Detection Heuristics**:
- Look for direct use of transfer amounts in state updates
- Check if balance differences are calculated
- Search for assumptions about token behavior
- Verify handling of: FOT tokens, rebasing tokens, tokens with hooks (ERC777)
- Check for tokens with more than 18 decimals
- Verify DAI permit handling (non-standard signature)
- Check for blocklist tokens (USDT, USDC) that can block transfers
- Verify support for tokens that revert on zero transfers (LEND)
- Check for proper decimal handling in liquidation pricing
- Handle fee-on-transfer tokens in depositGlp() scenarios
- Verify vault internal accounting matches actual token balances (PoolTogether M-01)
- Check for tokens like BNB that revert on zero approvals (Silo M-03)

### 2. CEI Pattern Violations
**Pattern**: External calls made before state updates, enabling reentrancy attacks.

**Vulnerable Code Example**:
```solidity
// VULNERABLE: Transfer before state update
token.safeTransferFrom(msg.sender, address(this), amount);
deposits.push(Deposit(msg.sender, amount, tokenAddress));
```

**Secure Implementation**:
```solidity
// Update state first
deposits.push(Deposit(msg.sender, 0, tokenAddress));
uint256 index = deposits.length - 1;
// Then make external call
token.safeTransferFrom(msg.sender, address(this), amount);
deposits[index].amount = amount;
```

**Detection Heuristics**:
- Identify all external calls
- Check if state changes occur after external calls
- Look for potential reentrancy vectors
- Consider read-only reentrancy risks
- Watch for native ETH transfers that can re-enter
- Check for ERC777 token callback reentrancy
- Verify hook implementations don't enable reentrancy (PoolTogether M-02)

### 3. First Depositor Attack (ERC4626 Specific)
**Pattern**: Attacker manipulates share price by being first depositor with minimal amount, then donating tokens directly.

**Attack Scenario**:
1. Attacker deposits 1 wei to get 1 share
2. Attacker donates large amount directly to vault
3. Subsequent depositors get 0 shares due to rounding

**Vulnerable Code Example (Astaria)**:
```solidity
// ERC4626Cloned has inconsistent deposit/mint logic on first deposit
function previewDeposit(uint256 assets) public view virtual returns (uint256) {
  return convertToShares(assets);
}

function previewMint(uint256 shares) public view virtual returns (uint256) {
  uint256 supply = totalSupply();
  return supply == 0 ? 10e18 : shares.mulDivUp(totalAssets(), supply);
}
```

**Mitigation**:
- Virtual shares/assets
- Minimum deposit requirements
- Initial deposit by protocol
- Dead shares (like Uniswap V2)
- Consistent logic between deposit and mint functions
- Set virtual assets equal to virtual shares (Silo M-06)

### 4. Share Price Manipulation
**Pattern**: Attackers manipulate exchange rates through donations or complex interactions.

**Detection**:
- Check for direct token transfers to vault
- Verify share calculation logic
- Look for rounding vulnerabilities
- Analyze sandwich attack possibilities
- Check for minimum deposit bypass vulnerabilities
- Verify exchange rate can actually increase (PoolTogether H-01)

### 5. Inflation/Deflation Attacks
**Pattern**: Manipulating share prices to steal funds or cause loss of funds.

**Vulnerable Scenarios**:
- Vault with no initial shares
- Low liquidity vaults
- Vaults accepting direct transfers
- Inconsistent rounding between deposit/mint and withdraw/redeem
- Exchange rate capped by flawed logic (PoolTogether H-01)
- Market rounding exploitation causing share deflation (Silo M-06)

### 6. State Ordering Issues
**Pattern**: Functions called in wrong order causing incorrect behavior.

**Examples**:
```solidity
// WRONG: Calling _refreshiBGT before pulling funds
_refreshiBGT(amount);
SafeTransferLib.safeTransferFrom(ibgt, msg.sender, address(this), amount);

// CORRECT: Pull funds first
SafeTransferLib.safeTransferFrom(ibgt, msg.sender, address(this), amount);
_refreshiBGT(amount);
```

### 7. ETH Transfer Method Issues
**Pattern**: Using transfer() or send() with fixed 2300 gas limit.

**Vulnerable Code**:
```solidity
// VULNERABLE: May fail with smart contract wallets
recipient.transfer(amount);
```

**Secure Implementation**:
```solidity
(bool success, ) = recipient.call{value: amount}("");
require(success, "ETH transfer failed");
```

### 8. Signature Replay Vulnerabilities
**Pattern**: Improper nonce handling allowing signature reuse.

**Vulnerable Code Example (Astaria)**:
```solidity
// VULNERABLE: Same commitment can be used multiple times
function _validateCommitment(IAstariaRouter.Commitment calldata params, address receiver) internal view {
    // Only validates signature, not preventing replay
    address recovered = ecrecover(
        keccak256(_encodeStrategyData(s, params.lienRequest.strategy, params.lienRequest.merkle.root)),
        params.lienRequest.v,
        params.lienRequest.r,
        params.lienRequest.s
    );
}
```

**Secure Implementation**:
```solidity
mapping(address => uint256) public nonces;
mapping(bytes32 => bool) public usedSignatures;

function withdraw(uint256 amount, uint256 nonce, bytes signature) {
    require(nonce == nonces[msg.sender], "Invalid nonce");
    bytes32 hash = keccak256(abi.encode(msg.sender, amount, nonce));
    require(!usedSignatures[hash], "Signature already used");
    // ... verify signature ...
    usedSignatures[hash] = true;
    nonces[msg.sender]++;
}
```

### 9. Interest/Reward Calculation Issues
**Pattern**: Incorrect interest accrual or reward distribution logic.

**Common Issues**:
- Not updating state before calculations
- Rounding errors accumulating over time
- Wrong variable usage in calculations
- Integer overflow/underflow
- Compounding interest when claiming simple interest
- Strategist reward calculated on loan amount instead of payment amount
- Dynamic emission rate not handled properly
- Rewards lost due to rounding in small positions
- Fee shares minted after reward distribution (Silo M-05)
- Missing totalSupply sync before claiming rewards (Silo M-02)

### 10. Cross-Function Reentrancy
**Pattern**: Reentrancy through multiple functions sharing state.

**Example**:
```solidity
function redeemYield(uint256 amount) external {
    // Burn YT tokens
    YieldToken(yt).burnYT(msg.sender, amount);
    // Calculate and send rewards (reentrancy point)
    for(uint i; i < yieldTokens.length; i++) {
        SafeTransferLib.safeTransfer(yieldTokens[i], msg.sender, claimable);
    }
}
```

### 11. Access Control Issues
**Pattern**: Missing or incorrect access control on critical functions.

**Examples**:
- Functions that should be owner-only but aren't
- Incorrect modifier usage
- Missing validation of caller identity
- Flash action callbacks missing initiator validation
- Clearing house functions callable by anyone
- Public compound functions allowing MEV exploitation
- Anyone can mint yield fees to arbitrary recipient (PoolTogether H-04)
- Draw manager can be front-run and set by attacker (PoolTogether M-06)
- Missing access control on mint/burn functions (USSD H-8)

### 12. Decimal Precision Issues
**Pattern**: Incorrect handling of tokens with different decimal places.

**Vulnerable Code Example (Astaria)**:
```solidity
// Wrong starting price for non-18 decimal assets
listedOrder = s.COLLATERAL_TOKEN.auctionVault(
  ICollateralToken.AuctionVaultParams({
    settlementToken: stack[position].lien.token,
    collateralId: stack[position].lien.collateralId,
    maxDuration: auctionWindowMax,
    startingPrice: stack[0].lien.details.liquidationInitialAsk, // Assumes 18 decimals
    endingPrice: 1_000 wei
  })
);
```

**Secure Approach**:
- Always normalize to a standard precision (e.g., 18 decimals)
- Be explicit about decimal conversions
- Test with tokens of various decimal places
- Handle tokens with more than 18 decimals carefully
- Account for decimal mismatches in minDepositAmount calculations
- Never assume oracle decimals (USSD H-4)

### 13. Liquidation and Bad Debt Handling
**Pattern**: Improper handling of underwater positions or bad debt.

**Key Checks**:
- Ensure liquidation incentives are properly set
- Handle cases where collateral value < debt
- Prevent liquidation griefing
- Ensure liquidations can't be blocked by reverting transfers
- Account for liquidator rewards in debt calculations
- Prevent self-liquidation exploitation
- Handle epoch processing when liens are open
- Verify liquidation can occur before borrower is in default
- Check if borrower can be liquidated
- Ensure debt can't be closed without full repayment
- Prevent liquidation while repayments are paused
- Handle token disallow effects on existing positions
- Provide grace period after repayments resume
- Validate liquidator repayment amounts
- Prevent infinite loan rollover
- Avoid sending repayments to zero address
- Ensure borrowers can always repay loans
- Credit repayments fully across multiple loans
- Incentivize liquidation of small positions
- Ensure liquidation improves health scores

### 14. Oracle and Price Feed Issues
**Pattern**: Vulnerabilities in price feed integration.

**Security Measures**:
- Use multiple oracle sources
- Implement staleness checks
- Add price deviation limits
- Handle oracle failures gracefully
- Check sequencer uptime on L2s
- Validate roundId, price > 0, and timestamp
- Consider oracle manipulation during market turbulence
- Check for inverted base/rate tokens (USSD H-1)
- Verify oracle decimal assumptions (USSD H-4)
- Always check for stale prices (USSD M-1)
- Handle circuit breaker min/max prices (USSD M-7)
- Ensure oracle units match expected denomination (USSD H-11)

### 15. Upgrade and Migration Risks
**Pattern**: Issues when upgrading vault implementations or migrating funds.

**Considerations**:
- Storage layout preservation
- Proper initialization of new variables
- Migration function security
- Pause mechanisms during upgrades
- vGMX/vGLP token presence preventing migration

### 16. Self-Transfer Exploits
**Pattern**: Functions that don't correctly handle self-transfers, allowing infinite points/rewards.

**Vulnerable Code Example** (AllocationVesting):
```solidity
// VULNERABLE: Doesn't handle self-transfer correctly
allocations[from].points = uint24(fromAllocation.points - points);
allocations[to].points = toAllocation.points + uint24(points);
```

**Mitigation**:
```solidity
error SelfTransfer();
if(from == to) revert SelfTransfer();
```

### 17. Missing State Updates Before Reward Claims
**Pattern**: Failing to update integral states before claiming rewards, resulting in loss of accrued rewards.

**Vulnerable Pattern**:
```solidity
// VULNERABLE: Missing _updateIntegrals before _fetchRewards
function fetchRewards() external {
    _fetchRewards(); // Updates lastUpdate without capturing pending rewards
}
```

**Secure Implementation**:
```solidity
function fetchRewards() external {
    _updateIntegrals(address(0), 0, totalSupply);
    _fetchRewards();
}
```

### 18. Single Borrower Liquidation Failures
**Pattern**: Liquidation logic that fails when only one borrower exists.

**Vulnerable Code**:
```solidity
// VULNERABLE: Skips liquidation when troveCount == 1
while (trovesRemaining > 0 && troveCount > 1) {
    // liquidation logic
}
```

**Impact**: Cannot liquidate the last borrower, especially critical during sunsetting.

### 19. Token Loss from Disabled Receivers
**Pattern**: Permanently lost tokens when disabled emissions receivers don't claim allocated emissions.

**Vulnerable Flow**:
1. Receiver gets voting allocation
2. Receiver is disabled
3. If receiver doesn't call `allocateNewEmissions`, tokens are lost forever

**Mitigation**: Allow anyone to call `allocateNewEmissions` for disabled receivers.

### 20. Downcast Overflow in Critical Functions
**Pattern**: Unsafe downcasting causing loss of user funds.

**Vulnerable Code**:
```solidity
struct AccountData {
    uint32 locked; // DANGEROUS: Can overflow with large deposits
}
accountData.locked = uint32(accountData.locked + _amount);
```

**Mitigation**: Use SafeCast and enforce invariants:
```solidity
require(totalSupply <= type(uint32).max * lockToTokenRatio);
```

### 21. Preclaim Limit Bypass
**Pattern**: Vesting limits can be bypassed through point transfers.

**Attack Flow**:
1. User preclaims maximum allowed
2. Transfers points to new address
3. New address has 0 preclaimed, can preclaim again

**Mitigation**: Transfer preclaimed amounts proportionally with points.

### 22. Collateral Gain Double-Claim
**Pattern**: Missing state updates allowing multiple claims of the same collateral gains.

**Vulnerable Pattern**:
```solidity
// VULNERABLE: Doesn't call _accrueDepositorCollateralGain
function claimCollateralGains(address recipient, uint256[] calldata collateralIndexes) external {
    // Direct claim without accruing first
}
```

### 23. Precision Loss in Reward Distribution
**Pattern**: Division before multiplication causing permanent loss of rewards.

**Vulnerable Pattern**:
```solidity
// First divides by total weight
uint256 votePct = receiverWeight / totalWeight;
// Then multiplies by emissions
uint256 amount = votePct * weeklyEmissions;
```

**Mitigation**: Avoid intermediate divisions:
```solidity
uint256 amount = (weeklyEmissions * receiverWeight) / totalWeight;
```

### 24. Array Length Limitations
**Pattern**: Fixed-size arrays causing panic reverts when limits exceeded.

**Vulnerable Code**:
```solidity
mapping(address => uint256[256] deposits) public depositSums;
// Panic if more than 256 collaterals
```

**Mitigation**: Add explicit checks and limits on array growth.

### 25. Dust Handling in Withdrawals
**Pattern**: Incorrect state updates when dust rounding results in zero remaining balance.

**Impact**: Storage inconsistency where system believes user has active locks with 0 balance.

### 26. Oracle Decimal Handling Errors
**Pattern**: Price feed calculations that only work correctly for 8 decimal oracles.

**Vulnerable Code Example (Y2K)**:
```solidity
nowPrice = (price1 * 10000) / price2;
nowPrice = nowPrice * int256(10**(18 - priceFeed1.decimals()));
return nowPrice / 1000000;
```

**Impact**:
- With 6 decimal feeds: Returns 10 decimal number (4 orders of magnitude off)
- With 18 decimal feeds: Returns 0 or reverts
- Only correct for 8 decimal feeds

**Mitigation**:
```solidity
nowPrice = (price1 * 10000) / price2;
nowPrice = nowPrice * int256(10**(priceFeed1.decimals())) * 100;
return nowPrice / 1000000;
```

### 27. Sequencer Downtime Blocking Critical Operations
**Pattern**: Critical functions that depend on oracle prices fail during L2 sequencer downtime.

**Vulnerable Code Example (Y2K)**:
```solidity
function triggerEndEpoch(uint256 marketIndex, uint256 epochEnd) public {
    // ... logic ...
    emit DepegInsurance(
        // ...
        getLatestPrice(insrVault.tokenInsured()) // Reverts during sequencer downtime
    );
}
```

**Impact**: Winners cannot withdraw despite epoch being over

**Mitigation**: For non-critical price usage (like event emissions), handle oracle failures gracefully

### 28. Total Loss with No Counterparty
**Pattern**: Users lose all deposits when no one deposits in the counterparty vault.

**Vulnerable Code Example (Y2K)**:
```solidity
function triggerDepeg(uint256 marketIndex, uint256 epochEnd) public {
    // If only hedge vault has deposits, risk vault has 0
    insrVault.setClaimTVL(epochEnd, riskVault.idFinalTVL(epochEnd)); // Sets to 0
    riskVault.setClaimTVL(epochEnd, insrVault.idFinalTVL(epochEnd));
    
    insrVault.sendTokens(epochEnd, address(riskVault)); // Sends all to risk
    riskVault.sendTokens(epochEnd, address(insrVault)); // Sends nothing back
}
```

**Impact**: Complete loss of deposits for users in single-sided markets

**Mitigation**: Allow full withdrawal when no counterparty exists

### 29. Approval-Based Withdrawal Griefing
**Pattern**: Incorrect approval checks allowing anyone to force withdrawals.

**Vulnerable Code Example (Y2K)**:
```solidity
function withdraw(uint256 id, uint256 assets, address receiver, address owner) external {
    if(msg.sender != owner && isApprovedForAll(owner, receiver) == false)
        revert OwnerDidNotAuthorize(msg.sender, owner);
    // Anyone can withdraw if receiver is approved!
}
```

**Impact**: Attackers can force winners to withdraw at inopportune times

**Mitigation**: Check approval for msg.sender, not receiver:
```solidity
if(msg.sender != owner && isApprovedForAll(owner, msg.sender) == false)
    revert OwnerDidNotAuthorize(msg.sender, owner);
```

### 30. Upward Depeg Triggering Insurance
**Pattern**: Insurance pays out when pegged asset is worth MORE than underlying.

**Vulnerable Code Example (Y2K)**:
```solidity
if (price1 > price2) {
    nowPrice = (price2 * 10000) / price1;
} else {
    nowPrice = (price1 * 10000) / price2;
}
// Calculates ratio of lower price, triggering depeg when asset appreciates
```

**Impact**: Risk users must pay out when they shouldn't (asset appreciation is positive)

**Mitigation**: Always calculate ratio as pegged/underlying, not min/max

### 31. Protocol-Specific Withdraw Parameter Mismatch
**Pattern**: Incorrect assumptions about protocol-specific withdraw functions.

**Vulnerable Code Example (Swivel)**:
```solidity
// Assumes all protocols use underlying amount for withdrawals
return IYearnVault(c).withdraw(a) >= 0;
// But Yearn's withdraw() takes shares, not assets!
```

**Impact**:
- With insufficient shares: Transaction reverts
- With excess shares: More assets withdrawn than expected, funds locked

**Mitigation**:
```solidity
uint256 pricePerShare = IYearnVault(c).pricePerShare();
return IYearnVault(c).withdraw(a / pricePerShare) >= 0;
```

### 32. VaultTracker State Inconsistency After Maturity
**Pattern**: Exchange rate can exceed maturity rate, causing underflow in subsequent operations.

**Vulnerable Code Example (Swivel)**:
```solidity
function removeNotional(address o, uint256 a) external {
    uint256 exchangeRate = Compounding.exchangeRate(protocol, cTokenAddr);
    // After maturity, exchangeRate > maturityRate
    if (maturityRate > 0) {
        yield = ((maturityRate * 1e26) / vlt.exchangeRate) - 1e26; // Underflows!
    }
}
```

**Impact**: Users cannot withdraw or claim interest after maturity

**Mitigation**:
```solidity
vlt.exchangeRate = (maturityRate > 0 && maturityRate < exchangeRate) ? maturityRate : exchangeRate;
```

### 33. Interface Definition Causing Function Calls to Fail
**Pattern**: Interface mismatch between caller and implementation.

**Vulnerable Code Example (Swivel)**:
```solidity
// MarketPlace calls:
ISwivel(swivel).authRedeem(p, u, market.cTokenAddr, t, a);

// But Swivel only has:
function authRedeemZcToken(uint8 p, address u, address c, address t, uint256 a) external
```

**Impact**: Critical functions permanently fail, locking user funds

**Mitigation**: Ensure interface definitions match implementations

### 34. Compounding Interest Calculation Missing Accrued Interest
**Pattern**: Interest calculations ignore previously accrued redeemable amounts.

**Vulnerable Code Example (Swivel)**:
```solidity
function addNotional(address o, uint256 a) external {
    uint256 yield = ((exchangeRate * 1e26) / vlt.exchangeRate) - 1e26;
    uint256 interest = (yield * vlt.notional) / 1e26; // Only uses notional!
    // Should use vlt.notional + vlt.redeemable
}
```

**Impact**: Users receive less yield than entitled over time

**Mitigation**: Include redeemable in yield calculations

### 35. Division Before Multiplication Causing Fund Loss
**Pattern**: Mathematical operations ordered incorrectly causing precision loss.

**Enhanced Pattern from Dacian's Research**:
Division in Solidity rounds down, hence to minimize rounding errors always perform multiplication before division.

**Vulnerable Code Example (Y2K)**:
```solidity
// In beforeWithdraw:
entitledAmount = amount.divWadDown(idFinalTVL[id]).mulDivDown(idClaimTVL[id], 1 ether);
// Can return 0 for small amounts
```

**Additional Example (Numeon)**:
```solidity
// Division before multiplication causes precision loss
uint256 scale0 = Math.mulDiv(amount0, 1e18, liquidity) * token0Scale;
uint256 scale1 = Math.mulDiv(amount1, 1e18, liquidity) * token1Scale;
```

**Additional Example (USSD)**:
```solidity
// VULNERABLE: Extra division by 1e18 causes massive precision loss
uint256 amountToSellUnits = IERC20Upgradeable(collateral[i].token).balanceOf(USSD) *
    ((amountToBuyLeftUSD * 1e18 / collateralval) / 1e18) / 1e18;
```

**Impact**: Users can call withdraw and receive 0 tokens; significant precision loss in calculations

**Mitigation**: Multiply before dividing:
```solidity
entitledAmount = (amount * idClaimTVL[id]) / idFinalTVL[id];
// Or for Numeon:
uint256 scale0 = Math.mulDiv(amount0 * token0Scale, 1e18, liquidity);
uint256 scale1 = Math.mulDiv(amount1 * token1Scale, 1e18, liquidity);
```

**Advanced Detection**: Expand function calls to reveal hidden division before multiplication:
```solidity
// iRate = baseVbr + utilRate.wmul(slope1).wdiv(optimalUsageRate)
// Expands to: baseVbr + utilRate * (slope1 / 1e18) * (1e18 / optimalUsageRate)
// Fix: iRate = baseVbr + utilRate * slope1 / optimalUsageRate;
```

### 36. Stale Oracle Price Acceptance
**Pattern**: Accepting oracle prices with timestamp = 0 or very old timestamps.

**Vulnerable Code Example (Y2K)**:
```solidity
function getLatestPrice(address _token) public view returns (int256 nowPrice) {
    // ...
    if(timeStamp == 0) // Should check for staleness, not just 0
        revert TimestampZero();
    return price;
}
```

**Impact**: Protocol operates on outdated prices

**Mitigation**:
```solidity
uint constant observationFrequency = 1 hours;
if(timeStamp < block.timestamp - uint256(observationFrequency))
    revert StalePrice();
```

### 37. Depeg Trigger on Exact Strike Price
**Pattern**: Depeg event triggers when price equals strike price, not just below.

**Vulnerable Code Example (Y2K)**:
```solidity
modifier isDisaster(uint256 marketIndex, uint256 epochEnd) {
    if(vault.strikePrice() < getLatestPrice(vault.tokenInsured()))
        revert PriceNotAtStrikePrice();
    // Allows depeg when price = strike price
    _;
}
```

**Impact**: Incorrect triggering of insurance events

**Mitigation**: Use `<=` instead of `<`

### 38. Reward Token Recovery Backdoor
**Pattern**: Admin can withdraw reward tokens that should be distributed to users.

**Vulnerable Code Example (Y2K)**:
```solidity
function recoverERC20(address tokenAddress, uint256 tokenAmount) external onlyOwner {
    require(tokenAddress != address(stakingToken), "Cannot withdraw staking token");
    // Missing: require(tokenAddress != address(rewardsToken))
    ERC20(tokenAddress).safeTransfer(owner, tokenAmount);
}
```

**Impact**: Admin can rug pull reward tokens

**Mitigation**: Prevent withdrawal of both staking and reward tokens

### 39. Reward Rate Dilution Attack
**Pattern**: Notifying rewards with 0 amount to dilute reward rate.

**Vulnerable Code Example (Y2K)**:
```solidity
function notifyRewardAmount(uint256 reward) external {
    if (block.timestamp >= periodFinish) {
        rewardRate = reward.div(rewardsDuration);
    } else {
        uint256 remaining = periodFinish.sub(block.timestamp);
        uint256 leftover = remaining.mul(rewardRate);
        rewardRate = reward.add(leftover).div(rewardsDuration); // Diluted with 0
    }
}
```

**Impact**: Reward rate can be reduced by 20% repeatedly

**Mitigation**: Prevent extending duration on every call or maintain constant rate

### 40. Expired Vault Tokens Earning Rewards
**Pattern**: Worthless expired tokens continue earning rewards.

**Vulnerable Code Example (Y2K)**:
```solidity
// After triggerEndEpoch:
insrVault.setClaimTVL(epochEnd, 0); // Makes tokens worthless
// But StakingRewards doesn't know and continues rewarding
```

**Impact**: Rewards stolen from future valid epochs

**Mitigation**: Add expiry validation in StakingRewards

## Yield Vault Specific Patterns

### 41. Yield Position Liquidation Bypass
**Pattern**: Collateral deposited to yield-generating positions (like Gamma Hypervisors) not being affected by liquidations.

**Vulnerable Code**:
```solidity
function liquidate() external onlyVaultManager {
    // Only liquidates regular collateral, not yield positions
    for (uint256 i = 0; i < tokens.length; i++) {
        if (tokens[i].symbol != NATIVE) liquidateERC20(IERC20(tokens[i].addr));
    }
    // Hypervisor tokens not included!
}
```

**Impact**: Users can have collateral in yield positions, get liquidated, and still withdraw the yield collateral.

### 42. Direct Removal of Yield Position Tokens
**Pattern**: Yield position tokens (like Hypervisor shares) can be removed without collateralization checks.

**Vulnerable Code**:
```solidity
function removeAsset(address _tokenAddr, uint256 _amount, address _to) external onlyOwner {
    ITokenManager.Token memory token = getTokenManager().getTokenIfExists(_tokenAddr);
    if (token.addr == _tokenAddr && !canRemoveCollateral(token, _amount)) revert Undercollateralised();
    // Hypervisor tokens not in TokenManager, so check bypassed!
    IERC20(_tokenAddr).safeTransfer(_to, _amount);
}
```

### 43. Self-Backing Stablecoin Issues
**Pattern**: Stablecoins backing themselves through LP positions create systemic risks.

**Example**: USDs/USDC pool where USDs counts as collateral for USDs loans.

**Impact**:
- Death spiral during de-peg events
- Breaks economic incentives for peg maintenance
- Up to 50% self-backing possible

### 44. Hardcoded Stablecoin Price Assumptions
**Pattern**: Assuming USD stablecoins always equal $1.

**Vulnerable Code**:
```solidity
if (_token0 == address(USDs) || _token1 == address(USDs)) {
    // Assumes both tokens = $1
    _usds += _underlying0 * 10 ** (18 - ERC20(_token0).decimals());
    _usds += _underlying1 * 10 ** (18 - ERC20(_token1).decimals());
}
```

**Impact**: Over-collateralization during de-peg events.

### 45. Excessive Slippage Tolerance
**Pattern**: Allowing up to 10% loss on yield deposits/withdrawals.

**Vulnerable Code**:
```solidity
function significantCollateralDrop(uint256 _pre, uint256 _post) private pure returns (bool) {
    return _post < 9 * _pre / 10; // 10% loss accepted!
}
```

### 46. Hardcoded DEX Pool Fees
**Pattern**: Fixed pool fees preventing optimal routing.

**Vulnerable Code**:
```solidity
fee: 3000, // Always uses 0.3% pool
```

**Impact**: Higher slippage, failed swaps, potential DoS of yield features.

### 47. Yield Position Data Removal Issues
**Pattern**: Admin removal of Hypervisor data locks user funds.

**Vulnerable Flow**:
1. Users deposit to Hypervisor
2. Admin calls `removeHypervisorData`
3. Users cannot withdraw - funds locked

### 48. Token Symbol vs Address Confusion
**Pattern**: Inconsistent handling of native tokens vs WETH.

**Issue**: Both ETH and WETH symbols map to WETH address, causing swap failures.

## Auto-Redemption Specific Patterns

### 49. Hypervisor Collateral Redemption Slippage Issues
**Pattern**: Auto redemption of Hypervisor collateral lacks slippage protection during withdrawal and redeposit.

**Vulnerable Code**:
```solidity
// No slippage protection in withdrawal
IHypervisor(_hypervisor).withdraw(
    _thisBalanceOf(_hypervisor), address(this), address(this),
    [uint256(0), uint256(0), uint256(0), uint256(0)] // Empty slippage params!
);

// No minimum amount out in swaps
ISwapRouter(uniswapRouter).exactInputSingle(
    ISwapRouter.ExactInputSingleParams({
        amountOutMinimum: 0, // No slippage protection!
        ...
    })
);
```

**Impact**: Vaults can become undercollateralized due to MEV sandwich attacks during auto redemption.

**Mitigation**:
- Add collateralization checks after redemption
- Implement minimum collateral percentage checks
- Use proper slippage parameters

### 50. Incorrect Swap Path Configuration
**Pattern**: Using wrong swap paths (e.g., collateral -> USDC instead of collateral -> USDs).

**Vulnerable Pattern**:
```solidity
// Wrong: swaps to USDC but expects USDs
_amountOut = ISwapRouter(_swapRouterAddress).exactInput(
    ISwapRouter.ExactInputParams({
        path: _swapPath, // collateral -> USDC path
        ...
    })
);
// No USDs balance change, vault becomes liquidatable
uint256 _usdsBalance = USDs.balanceOf(address(this));
```

**Impact**: Vaults become erroneously liquidatable as collateral is converted to wrong token.

**Mitigation**:
- Validate swap paths include correct output token
- Use separate input/output paths
- Add post-swap validation

### 51. Empty Mapping DoS
**Pattern**: Critical mappings never populated, blocking all functionality.

**Vulnerable Code**:
```solidity
mapping(address => address) hypervisorCollaterals;
mapping(address => bytes) swapPaths;
// No functions to populate these mappings!
```

**Impact**: Complete DoS of auto redemption functionality requiring redeployment.

**Mitigation**:
- Pre-populate mappings in constructor
- Add setter functions with access control
- Query from external contracts

### 52. Insufficient Access Control on Critical Functions
**Pattern**: External functions callable by anyone enabling griefing attacks.

**Vulnerable Code**:
```solidity
function performUpkeep(bytes calldata performData) external {
    // No access control - anyone can call!
    if (lastRequestId == bytes32(0)) {
        triggerRequest();
    }
}
```

**Attack Vectors**:
- Repeatedly trigger redemptions regardless of price
- Send USDs to vault to cause underflow in fulfillment
- Drain Chainlink subscription funds

**Mitigation**:
- Add Chainlink Automation forwarder access control
- Re-check trigger conditions
- Use balance diffs instead of direct balanceOf

### 53. Fulfilment Revert DoS
**Pattern**: Any revert in fulfillment permanently disables auto redemption.

**Vulnerable Pattern**:
```solidity
function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal {
    // Any revert here permanently sets lastRequestId != 0
    // ... risky operations ...
    lastRequestId = bytes32(0); // Never reached on revert
}
```

**Impact**: Permanent DoS requiring redeployment.

**Mitigation**:
- Never allow fulfillRequest to revert
- Validate response length/format
- Use try/catch for external calls
- Add admin reset function

### 54. Oracle Manipulation via Instantaneous Prices
**Pattern**: Using spot prices instead of TWAPs for trigger conditions.

**Vulnerable Code**:
```solidity
function checkUpkeep() external returns (bool upkeepNeeded, bytes memory) {
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0(); // Spot price!
    upkeepNeeded = sqrtPriceX96 <= triggerPrice;
}
```

**Impact**:
- Force auto redemption via flash loan manipulation
- MEV bots can front-run with JIT liquidity
- Vault owners can force debt repayment avoiding fees

**Mitigation**:
- Use TWAP with 15-30 minute intervals
- Re-check conditions in performUpkeep
- Add Chainlink price oracle integration

### 55. Unsafe Signed-Unsigned Casting
**Pattern**: Casting signed liquidity values to unsigned without checking sign.

**Vulnerable Code**:
```solidity
(, int128 _liquidityNet,,,,,,) = pool.ticks(_lowerTick);
_liquidity += uint128(_liquidityNet); // Can underflow if negative!
```

**Impact**:
- Massive overestimation of USDs needed
- Full vault redemption
- Potential revert causing DoS

**Mitigation**:
```solidity
if (_liquidityNet >= 0) {
    _liquidity = _liquidity + uint128(_liquidityNet);
} else {
    _liquidity = _liquidity - uint128(-_liquidityNet);
}
```

### 56. Concentrated Liquidity Tick Calculation Errors
**Pattern**: Incorrect tick range calculations for positive ticks.

**Vulnerable Code**:
```solidity
// Wrong for positive non-multiple ticks due to rounding
int24 _upperTick = _tick / _spacing * _spacing;
int24 _lowerTick = _upperTick - _spacing;
```

**Impact**: Incorrect USDs calculations, though unlikely due to decimal differences.

**Mitigation**: Account for tick sign in range calculations.

### 57. Missing Response Validation
**Pattern**: Not validating Chainlink Functions response data.

**Missing Checks**:
- Token is valid collateral or Hypervisor
- TokenID exists and is minted
- Vault address is non-zero
- Response length matches expected format

**Mitigation**: Add comprehensive validation before using response data.

### 58. Enhanced Hypervisor Slippage Vulnerabilities
**Pattern**: Auto redemption with yield positions lacks comprehensive slippage protection across withdrawal, swap, and redeposit operations.

**Vulnerable Code** (The Standard v2):
```solidity
// quickWithdraw with no slippage protection
IHypervisor(_hypervisor).withdraw(
    _thisBalanceOf(_hypervisor), address(this), address(this),
    [uint256(0), uint256(0), uint256(0), uint256(0)]
);

// Multiple swap operations with amountOutMinimum: 0
ISwapRouter(uniswapRouter).exactInputSingle(
    ISwapRouter.ExactInputSingleParams({
        amountOutMinimum: 0,
        sqrtPriceLimitX96: 0
        ...
    })
);
```

**Attack Scenario**:
1. Attacker monitors mempool for auto redemption transaction
2. Sandwiches the withdrawal/swap/redeposit operations
3. Vault becomes undercollateralized due to accumulated slippage

**Mitigation**:
- Implement collateral percentage checks before and after redemption
- Add minimum collateral retention requirements
- Use proper slippage parameters throughout the flow

### 59. Incorrect Function Parameter Routing
**Pattern**: Passing wrong addresses to critical functions in complex call chains.

**Vulnerable Code** (The Standard):
```solidity
// WRONG: Passing vault address instead of swap router
IRedeemable(_smartVault).autoRedemption(
    _smartVault, // Should be swapRouter!
    quoter,
    _token,
    _collateralToUSDCPath,
    _USDsTargetAmount,
    _hypervisor
);
```

**Impact**: Complete failure of functionality when wrong contract receives calls.

**Detection**: Trace all parameter passing through call chains, especially in auto-redemption flows.

### 60. Balance-Based Redemption Amount Vulnerabilities
**Pattern**: Using direct `balanceOf()` to calculate redemption amounts instead of tracking actual swapped amounts.

**Vulnerable Code**:
```solidity
// VULNERABLE: Can be manipulated by direct transfers
uint256 _usdsBalance = USDs.balanceOf(address(this));
minted -= _usdsBalance;
USDs.burn(address(this), _usdsBalance);
```

**Attack**: Send USDs directly to vault to cause underflow and DoS auto redemption.

**Mitigation**:
```solidity
// Use swap output amount
uint256 amountOut = ISwapRouter(router).exactInput(params);
minted -= amountOut;
USDs.burn(address(this), amountOut);
```

### 61. Collateral Percentage Validation Gaps
**Pattern**: Missing validation that vaults maintain healthy collateralization after auto redemption.

**Vulnerable Scenarios**:
- Vault already near liquidation threshold
- Significant slippage during redemption
- Division by zero when debt fully repaid

**Secure Implementation**:
```solidity
function validateCollateralPercentage(uint256 minPercentage) private view {
    if (minted == 0) return; // Handle zero debt case
    uint256 collateralPercentage = (usdCollateral() * HUNDRED_PC) / minted;
    require(collateralPercentage >= minPercentage, "Below min collateral");
}
```

### 62. Swap Path Validation Failures
**Pattern**: Not validating that swap paths produce expected output tokens.

**Vulnerable Example** (The Standard):
- Swap path configured as `collateral -> USDC` instead of `collateral -> USDs`
- Swap succeeds but no debt is repaid
- Vault becomes liquidatable due to lost collateral

**Mitigation**:
- Store both input and output paths
- Validate path endpoints match expected tokens
- Add post-swap balance checks

### 63. Hypervisor-Collateral Correspondence Validation
**Pattern**: Not validating that Hypervisor tokens correspond to their underlying collateral tokens.

**Vulnerable Code**:
```solidity
// No validation that hypervisor actually contains this collateral
if (hypervisorCollaterals[_token] != address(0)) {
    _hypervisor = _token;
    _token = hypervisorCollaterals[_hypervisor];
}
```

**Mitigation**: Validate hypervisor token pairs:
```solidity
function validHypervisorPair(address hypervisor, address collateral) private view returns (bool) {
    IHypervisor hyp = IHypervisor(hypervisor);
    return hyp.token0() == collateral || hyp.token1() == collateral;
}
```

## Weighted Pool and Storage Optimization Patterns

### 64. Storage Slot Boundary Errors in Packed Data
**Pattern**: Incorrect index boundary checks when handling packed storage across multiple slots.

**Vulnerable Code** (QuantAMM):
```solidity
// WRONG: Should be >= 4 for second slot
if (request.indexIn > 4 && request.indexOut < 4) {
    // Cross-slot logic
} else if (tokenIndex > 4) { // Should be >= 4
    index = tokenIndex - 4;
    targetWrappedToken = _normalizedSecondFourWeights;
}
```

**Impact**:
- Swaps involving token at boundary index (4) fail
- Cross-slot swaps become impossible
- Array out-of-bounds errors

**Mitigation**:
```solidity
// Correct boundary checks
if (tokenIndex >= 4) {
    index = tokenIndex - 4;
    targetWrappedToken = _normalizedSecondFourWeights;
}
```

### 65. Weight Multiplier Index Misalignment
**Pattern**: Mismatch between expected and actual positions of multipliers in packed storage.

**Vulnerable Code** (QuantAMM):
```solidity
// Storage expects: [w1,w2,w3,w4,m1,m2,m3,m4]
// But code stores: [w1,w2,w3,w4,m1,m2,0,0] for 6 tokens
int256 blockMultiplier = tokenWeights[tokenIndex + tokensInTokenWeights];
// Accesses wrong index for tokens 4-7
```

**Impact**: Incorrect weight interpolation leading to wrong swap amounts.

**Mitigation**: Ensure consistent multiplier positioning across all token counts.

### 66. Negative Multiplier Casting Errors
**Pattern**: Incorrect handling of negative values when casting from signed to unsigned integers.

**Vulnerable Code** (QuantAMM):
```solidity
if (multiplier > 0) {
    return uint256(weight) + FixedPoint.mulDown(uint256(multiplierScaled18), time);
} else {
    // WRONG: uint256(negative) creates huge positive number
    return uint256(weight) - FixedPoint.mulUp(uint256(multiplierScaled18), time);
}
```

**Mitigation**:
```solidity
return uint256(weight) - FixedPoint.mulUp(uint256(-multiplierScaled18), time);
```

### 67. Tokenization Index Calculation Errors
**Pattern**: Incorrect index calculations when processing tokens across storage slots.

**Vulnerable Code** (QuantAMM):
```solidity
if (totalTokens > 4) {
    tokenIndex = 4;  // Set for first slot
}
// Process first slot...
if (totalTokens > 4) {
    tokenIndex -= 4;  // WRONG: Resets to 0, breaking second slot
}
```

**Impact**: Weights for tokens 4-7 calculated with wrong multipliers.

### 68. Permission System Bypass Vulnerabilities
**Pattern**: Flawed permission checks allowing unauthorized access to restricted functions.

**Vulnerable Code** (QuantAMM):
```solidity
bool internalCall = msg.sender != address(this);
// Always true since contract doesn't call itself this way
require(internalCall || approvedPoolActions[_pool] & MASK_POOL_GET_DATA > 0);
```

**Impact**: Permission checks effectively bypassed.

**Mitigation**: Remove ambiguous internal call checks or properly implement self-calls.

### 69. Range Validation Logic Errors
**Pattern**: Copy-paste errors in validation logic for packed data.

**Vulnerable Code** (QuantAMM):
```solidity
require(
    _firstInt <= MAX32 && _firstInt >= MIN32 &&
    _secondInt <= MAX32 && _secondInt >= MIN32 &&
    _thirdInt <= MAX32 && _firstInt >= MIN32 &&  // Should be _thirdInt
    _fourthInt <= MAX32 && _firstInt >= MIN32 && // Should be _fourthInt
    // ... continues with same error
);
```

**Impact**: Invalid values can be packed, leading to unexpected behavior.

### 70. Stale Oracle Acceptance in Fallback Logic
**Pattern**: Accepting stale oracle data when backup oracles are unavailable.

**Vulnerable Code** (QuantAMM):
```solidity
if (oracleResult.timestamp > block.timestamp - staleness) {
    outputData[i] = oracleResult.data;
} else {
    // Check backup oracles
    for (uint j = 1; j < numAssetOracles; ) {
        // If no backups (numAssetOracles == 1), loop skipped
    }
    outputData[i] = oracleResult.data; // Uses stale data!
}
```

**Mitigation**: Revert when no fresh oracle data available.

### 71. Weight Update Permission Gaps
**Pattern**: Missing permission checks allowing unauthorized updates to critical timing parameters.

**Vulnerable Code** (QuantAMM):
```solidity
if (poolRegistryEntry & MASK_POOL_DAO_WEIGHT_UPDATES > 0) {
    require(msg.sender == daoRunner, "ONLYDAO");
} else if (poolRegistryEntry & MASK_POOL_OWNER_UPDATES > 0) {
    require(msg.sender == poolManager, "ONLYMANAGER");
}
// No else - anyone can update if no permissions set!
poolRuleSettings[_poolAddress].lastPoolUpdateRun = _time;
```

**Mitigation**: Add else clause to revert on missing permissions.

### 72. Integer Overflow in Weight Calculations
**Pattern**: Unchecked arithmetic in time-based calculations causing overflow.

**Vulnerable Code** (QuantAMM):
```solidity
if (blockMultiplier == 0) {
    blockTimeUntilGuardRailHit = type(int256).max;
}
// Later...
currentLastInterpolationPossible += int40(uint40(block.timestamp)); // Overflow!
```

**Mitigation**: Guard against overflow conditions:
```solidity
if(currentLastInterpolationPossible < int256(type(int40).max)) {
    currentLastInterpolationPossible += int40(uint40(block.timestamp));
}
```

### 73. Extreme Weight Ratio Vulnerabilities
**Pattern**: Mathematical overflow when handling pools with extreme weight ratios.

**Example** (QuantAMM):
```solidity
// With weight = 0.01166 (1.166%), balance = 7.5M tokens, invariantRatio = 3.0
newBalance = oldBalance * (invariantRatio ^ (1/weight))
          = 7500e21 * (3.0 ^ 85.76)
          = OVERFLOW
```

**Impact**: DoS for unbalanced liquidity operations.

**Mitigation**: Enforce higher minimum weight thresholds (e.g., 3% instead of 0.1%).

### 74. Cross-Chain Token Transfer Value Loss (ERC4626 + LayerZero)
**Pattern**: ERC4626 vaults implementing cross-chain transfers via mint/burn approach instead of lock/unlock, causing share value distortion.

**Vulnerable Code Example** (D2):
```solidity
function _debit(address _from, uint256 _amountLD, uint256 _minAmountLD, uint32 _dstEid) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
    (amountSentLD, amountReceivedLD) = _debitView(_amountLD, _minAmountLD, _dstEid);
    _burn(_from, amountSentLD); // VULNERABLE: Reduces totalSupply, increasing share value
}
```

**Impact**:
- Users transferring tokens cross-chain lose value if others withdraw during transit
- Share price manipulation opportunity
- Complete loss of funds possible

**Mitigation**:
```solidity
// Use lock/unlock approach instead
function _debit(address _from, uint256 _amountLD, uint256 _minAmountLD, uint32 _dstEid) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
    (amountSentLD, amountReceivedLD) = _debitView(_amountLD, _minAmountLD, _dstEid);
    _transfer(_from, address(this), amountSentLD); // Lock tokens instead of burning
}
```

### 75. Missing Callback Implementation for External Protocol Integration
**Pattern**: Setting contract as callback receiver without implementing required interface, causing transaction reverts.

**Vulnerable Code Example** (D2 GMXV2):
```solidity
function gmxv2_withdraw(...) external {
    IExchangeRouter.CreateWithdrawalParams memory params = IExchangeRouter.CreateWithdrawalParams({
        receiver: address(this),
        callbackContract: address(this), // VULNERABLE: No callback implementation
        // ...
    });
}
```

**Impact**: Complete functionality loss, funds locked in protocol

**Mitigation**: Either implement required callbacks or set to zero address

### 76. Unsafe Token Transfer Without Validation
**Pattern**: Using standard ERC20 transfer/transferFrom without checking return values.

**Vulnerable Code Example** (D2 VaultV3):
```solidity
function custodyFunds() external onlyTrader notCustodied duringEpoch returns (uint256) {
    custodied = true;
    custodiedAmount = amount;
    IERC20(asset()).transfer(trader, amount); // VULNERABLE: No success check
    emit FundsCustodied(epochId, amount);
}
```

**Impact**: State inconsistencies if transfer fails silently

**Mitigation**: Use SafeERC20 library

### 77. Missing Slippage Protection in DeFi Integrations
**Pattern**: Hardcoded zero slippage parameters in swap/liquidity operations.

**Vulnerable Code Example** (D2 Pendle):
```solidity
router.addLiquiditySingleToken(
    address(this),
    address(market),
    0, // VULNERABLE: minLpOut hardcoded to 0
    approxParams,
    input,
    limitOrderData
);
```

**Impact**: MEV exploitation, sandwich attacks, value extraction

**Mitigation**: Allow configurable slippage parameters

### 78. Incorrect External Protocol Interface
**Pattern**: Using wrong function signatures for external protocol calls.

**Vulnerable Code Example** (D2 Berachain):
```solidity
// Contract uses:
function getReward(address account) external;
// But actual interface is:
function getReward(address account, address recipient) external;
```

**Impact**: Complete feature failure, inability to claim rewards

### 79. Chain ID Validation Errors
**Pattern**: Incorrect chain IDs preventing proper deployment configuration.

**Vulnerable Code Example** (D2):
```solidity
} else if (block.chainid == 80000) { // WRONG: Berachain is 80094
```

**Impact**: Wrong configuration deployed, missing functionality

### 80. Missing Output Token Validation in Swaps
**Pattern**: Only validating input tokens but not output tokens in swap operations.

**Vulnerable Code Example** (D2 Kodiak):
```solidity
function bera_kodiakv2_swap(address token, uint amount, uint amountMin, address[] calldata path) external {
    validateToken(token); // Only validates input
    // Missing: validateToken(path[path.length-1])
}
```

**Impact**: Tokens can become permanently stuck if swapped to non-approved assets

### 81. Improper Access Control Assignment
**Pattern**: Giving admin roles to operational accounts that shouldn't have them.

**Vulnerable Code Example** (D2):
```solidity
s.grantRole(ADMIN_ROLE, args._trader); // DANGEROUS: Trader can revoke owner's access
s.grantRole(EXECUTOR_ROLE, args._trader);
```

**Impact**: Compromised trader can lock out legitimate admins

### 82. Missing Deadline Protection in DEX Operations
**Pattern**: Using infinite deadlines or no deadlines in time-sensitive operations.

**Vulnerable Code Example** (D2):
```solidity
kodiakv2.addLiquidity(..., type(uint256).max); // Infinite deadline
```

**Impact**: Transactions can execute at unexpected times, MEV exploitation

### 83. Incorrect Approval Target
**Pattern**: Approving wrong contract for token operations.

**Vulnerable Code Example** (D2 Silo):
```solidity
function silo_execute(ISiloRouter.Action[] calldata actions) external {
    IERC20(actions[0].asset).approve(actions[0].silo, actions[0].amount); // Should approve router
    router.execute(actions);
}
```

### 84. Missing LTV Checks Across Protocols
**Pattern**: Inconsistent risk management when integrating multiple lending protocols.

**Vulnerable Code Example** (D2):
```solidity
// Aave has LTV check:
require(totalDebtBase <= maxDebtBase, "borrow amount exceeds max LTV");
// But Silo and Dolomite are missing this check
```

**Impact**: Higher liquidation risk, inconsistent risk profile

### 85. Borrowing Non-Approved Tokens
**Pattern**: Allowing borrowing of tokens that bypass trading restrictions.

**Impact**: Undermines asset control mechanisms

### 86. Permissionless External Reward Claims Leading to Locked Funds
**Pattern**: External protocols allowing anyone to claim rewards on behalf of other users, bypassing the vault's reward handling logic.

**Vulnerable Code Example** (Dolomite):
```solidity
// External protocol allows permissionless claiming
function getRewardForUser(address _user) public {
    // Anyone can call this on any user
    rewards[_user][_rewardsToken] = 0;
    _rewardsToken.transfer(_user, reward);
}

// Vault expects to handle rewards through its own logic
function _performDepositRewardByRewardType(...) internal {
    // This logic is bypassed when rewards are claimed externally
}
```

**Impact**:
- Rewards sent directly to vault address without proper handling
- Tokens stuck in contract without being staked or distributed
- Requires upgrades to recover funds

**Mitigation**:
```solidity
function _performDepositRewardByRewardType(...) internal {
    // Add existing balance to reward amount
    _amount += IERC20(token).balanceOf(address(this));
}
```

### 87. Counterintuitive Exit Behavior with Automatic Re-staking
**Pattern**: Exit functions that claim to fully exit but automatically re-stake rewards, leaving users partially invested.

**Vulnerable Code Example** (Dolomite):
```solidity
function _exit() internal {
    vault.exit(); // Unstakes original deposit
    _handleRewards(rewards); // But re-stakes rewards!
}

function _handleRewards(UserReward[] memory _rewards) internal {
    if (_rewards[i].token == UNDERLYING_TOKEN()) {
        // Automatically re-stakes iBGT rewards
        factory.depositIntoDolomiteMargin(DEFAULT_ACCOUNT_NUMBER, _rewards[i].amount);
    }
}
```

**Impact**:
- Users believe they've fully exited but still have staked positions
- Poor UX when "exit" doesn't mean complete exit
- Rewards may remain locked indefinitely

**Mitigation**: Avoid re-staking during explicit exit calls or clearly document the behavior

### 88. Missing Validation in Proxy Constructor Initialization
**Pattern**: Proxy constructors accepting arbitrary calldata without validating function selectors or parameters.

**Vulnerable Code Example** (Dolomite):
```solidity
constructor(
    address _berachainRewardsRegistry,
    bytes memory _initializationCalldata
) {
    // No validation of calldata content
    Address.functionDelegateCall(
        implementation(),
        _initializationCalldata,
        "Initialization failed"
    );
}
```

**Impact**:
- Proxy could be initialized with invalid parameters
- Zero addresses could be set for critical components
- Unexpected functions could be called during deployment

**Mitigation**:
```solidity
// Validate function selector
require(bytes4(_initializationCalldata[0:4]) == bytes4(keccak256("initialize(address)")));
// Validate parameters
address vaultFactory = abi.decode(_initializationCalldata[4:], (address));
require(vaultFactory != address(0), "Zero vault factory");
```

### 89. Reward Loss During Vault Type Transitions
**Pattern**: Changing reward vault types without properly claiming rewards from the previous type.

**Vulnerable Code Example** (Dolomite):
```solidity
function _setDefaultRewardVaultTypeByAsset(address _asset, RewardVaultType _type) internal {
    RewardVaultType currentType = getDefaultRewardVaultTypeByAsset(_asset);
    if (currentType != _type) {
        _getReward(_asset); // Always tries to get from INFRARED type
        REGISTRY().setDefaultRewardVaultTypeFromMetaVaultByAsset(_asset, _type);
    }
}

function _getReward(address _asset) internal {
    // Hardcoded to INFRARED, ignoring user's current type
    RewardVaultType rewardVaultType = RewardVaultType.INFRARED;
    IInfraredVault rewardVault = IInfraredVault(REGISTRY().rewardVault(_asset, rewardVaultType));
}
```

**Impact**: Permanent loss of rewards when transitioning between vault types

### 90. Reward Inaccessibility During Protocol Pause
**Pattern**: Automatic re-investment of rewards failing when staking is paused, with no alternative redemption path.

**Vulnerable Code Example** (Dolomite):
```solidity
function _handleRewards(UserReward[] memory _rewards) internal {
    if (_rewards[i].token == UNDERLYING_TOKEN()) {
        // Attempts to re-stake, will fail if paused
        factory.depositIntoDolomiteMargin(DEFAULT_ACCOUNT_NUMBER, _rewards[i].amount);
    }
}

// External vault has pausable staking
function stake(uint256 amount) external whenNotPaused {
    // Will revert when paused
}
```

**Impact**: Users cannot access earned rewards during pause periods

**Mitigation**: Check pause status before re-investing, provide alternative paths

### 91. Inconsistent ETH Handling in Proxy Patterns
**Pattern**: Different proxy contracts handling ETH differently through receive() and fallback() functions.

**Examples**:
```solidity
// Some proxies delegate both
receive() external payable { _callImplementation(implementation()); }
fallback() external payable { _callImplementation(implementation()); }

// Others only delegate fallback
receive() external payable {} // Empty
fallback() external payable { _callImplementation(implementation()); }
```

**Impact**: Confusion and potential ETH handling issues

### 92. Re-entrancy Guard Bypass Through Malicious Hooks (Bunni v2)
**Pattern**: Pools configured with malicious hooks can bypass the main contract's re-entrancy guard by calling unlock functions directly.

**Vulnerable Code Example** (Bunni v2):
```solidity
function lockForRebalance(PoolKey calldata key) external notPaused(6) {
    if (msg.sender != address(key.hooks)) revert BunniHub__Unauthorized();
    _nonReentrantBefore();
}

function unlockForRebalance(PoolKey calldata key) external notPaused(7) {
    if (msg.sender != address(key.hooks)) revert BunniHub__Unauthorized();
    _nonReentrantAfter();
}
```

**Attack Scenario**:
1. Deploy malicious hook contract
2. Hook calls `unlockForRebalance()` to disable re-entrancy protection
3. Recursive calls to `hookHandleSwap()` drain raw balances and vault reserves
4. State is set instead of decremented, avoiding underflow

**Impact**: Complete drainage of all legitimate pools' funds ($7.33M at time of disclosure)

**Mitigation**:
- Implement per-pool re-entrancy protection
- Constrain hooks to canonical implementations
- Add hook whitelist

### 93. Cross-Contract Re-entrancy in Token Transfers (Bunni v2)
**Pattern**: Token transfer hooks executed before unlocker callbacks can enable cross-contract re-entrancy.

**Vulnerable Code Example**:
```solidity
function transfer(address to, uint256 amount) public virtual override returns (bool) {
    ...
    _afterTokenTransfer(msgSender, to, amount);
    
    // Unlocker callback if `to` is locked.
    if (toLocked) {
        IERC20Unlocker unlocker = unlockerOf(to);
        unlocker.lockedUserReceiveCallback(to, amount);
    }
    return true;
}
```

**Impact**:
- Hooklet executes over intermediate state
- Locked receivers can manipulate state during transfer
- Referral reward accounting corruption

**Mitigation**: Execute hooks after all callbacks complete

### 94. Vault Fee Edge Cases in Raw Balance Updates
**Pattern**: Incorrect accounting when vaults don't pull expected asset amounts during deposits/withdrawals.

**Vulnerable Code Example** (Bunni v2):
```solidity
function _updateVaultReserveViaClaimTokens(int256 rawBalanceChange, Currency currency, ERC4626 vault)
    internal
    returns (int256 reserveChange, int256 actualRawBalanceChange)
{
    ...
    reserveChange = vault.deposit(absAmount, address(this)).toInt256();
    
    // it's safe to use absAmount here since at worst the vault.deposit() call pulled less token
    // than requested
    actualRawBalanceChange = -absAmount.toInt256(); // VULNERABLE: Assumes full amount deposited
    ...
}
```

**Impact**:
- Incorrect raw balance accounting
- Small losses to liquidity providers
- Potential rebalance order inflation

**Mitigation**: Use actual balance changes instead of assumed amounts

### 95. Insufficient Vault Decimals Handling
**Pattern**: Assuming vault share token decimals match underlying asset decimals.

**Vulnerable Code Example** (Bunni v2):
```solidity
// compute current share prices
uint120 sharePrice0 =
    bunniState.reserve0 == 0 ? 0 : reserveBalance0.divWadUp(bunniState.reserve0).toUint120();
uint120 sharePrice1 =
    bunniState.reserve1 == 0 ? 0 : reserveBalance1.divWadUp(bunniState.reserve1).toUint120();
```

**Real Example**: Morpho vault with 18-decimal shares for 8-decimal WBTC

**Impact**:
- Erroneous surge triggering
- Share price overflow causing DoS
- Incorrect fee calculations

**Mitigation**: Explicitly scale values based on actual decimals

### 96. Oracle Tick Validation Gaps
**Pattern**: Missing validation of oracle-derived ticks in various LDF functions.

**Vulnerable Code Example** (Bunni v2):
```solidity
function floorPriceToRick(uint256 floorPriceWad, int24 tickSpacing) public view returns (int24 rick) {
    // No validation that rick is within usable range
    uint160 sqrtPriceX96 = ((floorPriceWad << 192) / WAD).sqrt().toUint160();
    rick = sqrtPriceX96.getTickAtSqrtPrice();
    rick = bondLtStablecoin ? rick : -rick;
    rick = roundTickSingle(rick, tickSpacing);
}
```

**Impact**: Operations could execute outside usable tick ranges

### 97. Dynamic LDF Shift Mode DoS
**Pattern**: Enforcing shift modes without validating resulting tick bounds can cause DoS.

**Vulnerable Code Example** (Bunni v2):
```solidity
if (initialized) {
    int24 tickLength = tickUpper - tickLower;
    tickLower = enforceShiftMode(tickLower, lastTickLower, shiftMode);
    tickUpper = tickLower + tickLength; // Can exceed maxUsableTick!
    shouldSurge = tickLower != lastTickLower;
}
```

**Impact**: Complete DoS of pool operations requiring LDF queries

### 98. Fee Calculation Overflow with am-AMM
**Pattern**: Total fees exceeding 100% when am-AMM surge fee is active.

**Vulnerable Code Example** (Bunni v2):
```solidity
// Surge fee can be 100%
swapFee = useAmAmmFee
    ? uint24(FixedPointMathLib.max(amAmmSwapFee, computeSurgeFee(lastSurgeTimestamp, hookParams.surgeFeeHalfLife)))
    : hookFeesBaseSwapFee;
    
// Hook fees added on top
if(useAmAmmFee) {
    hookFeesAmount = outputAmount.mulDivUp(hookFeesBaseSwapFee, SWAP_FEE_BASE).mulDivUp(
        env.hookFeeModifier, MODIFIER_BASE
    );
}

// Total can exceed outputAmount!
outputAmount -= swapFeeAmount + hookFeesAmount;
```

**Impact**: Unexpected reverts during swaps

### 99. Queued Withdrawal Timestamp Overflow
**Pattern**: Unchecked arithmetic for withdrawal timestamps causing edge case failures.

**Vulnerable Code Example** (Bunni v2):
```solidity
// use unchecked to get unlockTimestamp to overflow back to 0 if overflow occurs
uint56 newUnlockTimestamp;
unchecked {
    newUnlockTimestamp = uint56(block.timestamp) + WITHDRAW_DELAY;
}
// But later:
if (queued.unlockTimestamp + WITHDRAW_GRACE_PERIOD >= block.timestamp) { // Can overflow!
    revert BunniHub__NoExpiredWithdrawal();
}
```

**Impact**: Permanent DoS of queued withdrawals near uint56 max

### 100. Just-In-Time (JIT) Liquidity Inflation
**Pattern**: JIT liquidity added before swaps that trigger rebalances can inflate order amounts.

**Attack Scenario** (Bunni v2):
1. Add JIT liquidity before swap
2. Swap triggers rebalance with inflated amounts
3. Rebalance order requires excessive liquidity
4. Withdrawals in other pools potentially DoS'd

**Impact**: Less profitable rebalance fulfillment, potential DoS

### 101. Liquidity Distribution State Gaps in Hooklets
**Pattern**: Hooklets not receiving reserve change information during rebalancing operations.

**Issue** (Bunni v2): While deposit/withdraw/swap hooklets receive detailed return data including amount changes, rebalancing operations provide no such information.

**Impact**: Cannot implement advanced strategies based on rebalancing flows

### 102. Narrow Type Upper Bits in Allowance Calculations
**Pattern**: Potentially dirty upper bits of addresses affecting keccak256 hash calculations.

**Vulnerable Code Example** (Bunni v2):
```solidity
function approve(address spender, uint256 amount) public virtual override returns (bool) {
    assembly {
        // Compute the allowance slot and store the amount.
        mstore(0x20, spender) // Upper bits might be dirty
        mstore(0x0c, _ALLOWANCE_SLOT_SEED)
        mstore(0x00, msgSender)
        sstore(keccak256(0x0c, 0x34), amount)
    }
}
```

**Impact**: Incorrect allowance slot computation

### 103. Missing Minimum Shares Slippage Protection
**Pattern**: Deposits only validate token amounts but not received shares.

**Vulnerable Code Example** (Bunni v2):
```solidity
// check slippage
if (amount0 < params.amount0Min || amount1 < params.amount1Min) {
    revert BunniHub__SlippageTooHigh();
}
// But no check on shares received!
```

**Attack with Malicious Vault**:
1. Vault inflates its share price before victim deposit
2. Victim receives minimal shares despite passing slippage check
3. Attacker profits from inflated share value

**Mitigation**: Add `sharesMin` parameter to deposit params

### 104. Missing CCIP Source Validation (YieldFi)
**Pattern**: Cross-chain message handlers not validating the sender, allowing arbitrary message injection.

**Vulnerable Code Example** (YieldFi):
```solidity
function _ccipReceive(Client.Any2EVMMessage memory any2EvmMessage) internal override {
    bytes memory message = abi.decode(any2EvmMessage.data, (bytes));
    BridgeSendPayload memory payload = Codec.decodeBridgeSendPayload(message);
    // No validation of message sender!
    
    if (isL1) {
        ILockBox(lockboxes[payload.token]).unlock(payload.token, payload.to, payload.amount);
    } else {
        // Mint tokens on L2
        IManager(manager).manageAssetAndShares(payload.to, manageAssetAndShares);
    }
}
```

**Impact**: Attackers can drain lockboxes on L1 or mint unlimited tokens on L2

**Mitigation**: Implement trusted peer validation:
```solidity
mapping(uint64 => mapping(address => bool)) public allowedPeers;
address sender = abi.decode(any2EvmMessage.sender, (address));
require(allowedPeers[any2EvmMessage.sourceChainSelector][sender], "!allowed");
```

### 105. CCIP Chain ID Type Mismatch (YieldFi)
**Pattern**: Using incorrect data types for cross-chain identifiers causing message decoding failures.

**Vulnerable Code Example** (YieldFi):
```solidity
// Codec expects uint32 for chain ID
(uint32 dstId, address to, address token, uint256 amount, bytes32 trxnType) =
    abi.decode(_data, (uint32, address, address, uint256, bytes32));

// But CCIP uses uint64 chain selectors (e.g., Ethereum: 5009297550715157269)
```

**Impact**: All CCIP messages revert during decoding, causing permanent fund loss

**Mitigation**: Update chain ID type to uint64

### 106. Wrong Owner in Delegated Withdrawals (YieldFi)
**Pattern**: Passing incorrect owner address to downstream functions in delegated withdrawal scenarios.

**Vulnerable Code Example** (YieldFi):
```solidity
function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares)
    internal override {
    if (caller != owner) {
        _spendAllowance(owner, caller, shares);
    }
    // VULNERABLE: Passing msg.sender instead of owner
    IManager(manager).redeem(msg.sender, address(this), asset(), shares, receiver, address(0), "");
}
```

**Impact**: Delegated withdrawals fail or burn wrong user's tokens

**Mitigation**: Pass correct `owner` parameter

### 107. Incorrect ERC4626 Rounding Direction (YieldFi)
**Pattern**: Preview functions rounding in favor of users instead of the vault.

**Vulnerable Code Example** (YieldFi L2):
```solidity
// previewMint - should round up (against user)
function previewMint(uint256 shares) public view override returns (uint256) {
    return (grossShares * exchangeRate()) / Constants.PINT; // Rounds down!
}

// previewWithdraw - should round up (against user)
function previewWithdraw(uint256 assets) public view override returns (uint256) {
    uint256 sharesWithoutFee = (assets * Constants.PINT) / exchangeRate(); // Rounds down!
}
```

**Impact**: Slow value leak from vault through rounding errors

**Mitigation**: Implement proper rounding direction per EIP-4626

### 108. Missing L2 Sequencer Uptime Check (YieldFi)
**Pattern**: Not verifying L2 sequencer status when reading oracle data.

**Vulnerable Code Example** (YieldFi):
```solidity
function fetchExchangeRate(address token) external view returns (uint256) {
    (, int256 answer,, uint256 updatedAt,) = IOracle(oracle).latestRoundData();
    require(answer > 0, "Invalid price");
    require(block.timestamp - updatedAt < staleThreshold, "Stale price");
    // Missing sequencer uptime check!
}
```

**Impact**: Stale prices appear fresh during sequencer downtime

**Mitigation**: Add sequencer uptime validation for L2 deployments

### 109. Direct Deposits Below Withdrawal Threshold (YieldFi)
**Pattern**: Allowing deposits that result in shares below minimum withdrawal amount.

**Vulnerable Code Example** (YieldFi):
```solidity
// YToken deposit has no minimum check
function _deposit(...) internal {
    require(receiver != address(0) && assets > 0 && shares > 0, "!valid");
    // No check against minSharesInYToken!
}

// But Manager withdrawal enforces minimum
function _validate(...) internal {
    require(_amount >= minSharesInYToken[_yToken], "!minShares");
}
```

**Impact**: Users can deposit amounts that become permanently locked

**Mitigation**: Enforce minimum shares in YToken deposits

### 110. Invalid Fee Share Calculation (YieldFi)
**Pattern**: Returning wrong value when fee is zero causing underflow.

**Vulnerable Code Example** (YieldFi):
```solidity
function _transferFee(address _yToken, uint256 _shares, uint256 _fee) internal returns (uint256) {
    if (_fee == 0) {
        return _shares; // WRONG: Should return 0
    }
    uint256 feeShares = (_shares * _fee) / Constants.HUNDRED_PERCENT;
    IERC20(_yToken).safeTransfer(treasury, feeShares);
    return feeShares;
}

// Later causes underflow:
uint256 sharesAfterAllFee = adjustedShares - adjustedFeeShares - adjustedGasFeeShares;
```

**Impact**: Deposits with zero fee revert

**Mitigation**: Return 0 when fee is 0

### 111. Incorrect Redemption Accounting in Yield Distribution (Critical)
**Pattern**: When processing redemptions during yield phase, incorrectly including yield in the base assets calculation that gets decremented from tracked deposits.

**Vulnerable Code Example** (Strata):
```solidity
function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares) internal override {
    if (PreDepositPhase.YieldPhase == currentPhase) {
        assets += previewYield(caller, shares); // Adds yield
        uint sUSDeAssets = sUSDe.previewWithdraw(assets);
        
        _withdraw(
            address(sUSDe),
            caller,
            receiver,
            owner,
            assets, // This includes yield but gets decremented from depositedBase!
            sUSDeAssets,
            shares
        );
    }
}

// In MetaVault
function _withdraw(..., uint256 baseAssets, ...) internal {
    depositedBase -= baseAssets; // Underflows when baseAssets includes yield
}
```

**Impact**:
- Deposited base tracking becomes corrupted
- Subsequent yield calculations amplify the error
- Attackers can drain entire protocol balance

**Mitigation**:
```solidity
uint256 assetsPlusYield = assets + previewYield(caller, shares);
uint sUSDeAssets = sUSDe.previewWithdraw(assetsPlusYield);
_withdraw(
    address(sUSDe),
    caller,
    receiver,
    owner,
    assets, // Only base assets, not including yield
    sUSDeAssets,
    shares
);
```

### 112. Multi-Vault Withdrawal Failures During Phase Transitions (High)
**Pattern**: Supported vault assets become inaccessible during yield phase due to incorrect withdrawal logic.

**Vulnerable Code Example** (Strata):
```solidity
function _withdraw(address caller, address receiver, address owner, uint256 assets, uint256 shares) internal override {
    if (PreDepositPhase.YieldPhase == currentPhase) {
        // Only handles sUSDe withdrawals
        uint sUSDeAssets = sUSDe.previewWithdraw(assets);
        _withdraw(address(sUSDe), ...);
        return;
    }
    
    // Points phase logic
    uint USDeBalance = USDe.balanceOf(address(this));
    if (assets > USDeBalance) {
        redeemRequiredBaseAssets(assets - USDeBalance);
    }
}
```

**Impact**: Users who deposited via supported vaults cannot withdraw their entitled assets during yield phase.

**Mitigation**: Add logic to handle supported vault withdrawals during yield phase or prevent adding vaults during yield phase.

### 113. Incomplete Multi-Vault Redemption Logic (Medium)
**Pattern**: `redeemRequiredBaseAssets` only withdraws from a vault if that single vault can satisfy the entire requested amount.

**Vulnerable Code Example** (Strata):
```solidity
function redeemRequiredBaseAssets(uint baseTokens) internal {
    for (uint i = 0; i < assetsArr.length; i++) {
        IERC4626 vault = IERC4626(assetsArr[i].asset);
        uint totalBaseTokens = vault.previewRedeem(vault.balanceOf(address(this)));
        if (totalBaseTokens >= baseTokens) { // Only withdraws if single vault sufficient
            vault.withdraw(baseTokens, address(this), address(this));
            break;
        }
    }
}
```

**Impact**:
- Withdrawals fail even when sufficient assets exist across multiple vaults
- Excess assets withdrawn remain unstaked

**Mitigation**: Implement logic to withdraw from multiple vaults and track remaining amount needed.

### 114. Preview Function Violations with Unchecked Reverts (Medium)
**Pattern**: Using `previewRedeem` instead of `maxWithdraw` for availability checks, causing DoS when vaults are paused or have limits.

**Vulnerable Code Example** (Strata):
```solidity
function redeemRequiredBaseAssets(uint baseTokens) internal {
    for (uint i = 0; i < assetsArr.length; i++) {
        IERC4626 vault = IERC4626(assetsArr[i].asset);
        // previewRedeem doesn't account for pause states or limits
        uint totalBaseTokens = vault.previewRedeem(vault.balanceOf(address(this)));
        if (totalBaseTokens >= baseTokens) {
            vault.withdraw(baseTokens, address(this), address(this));
        }
    }
}
```

**EIP-4626 Specification**: `previewRedeem` MUST NOT account for redemption limits and should act as though redemption would be accepted.

**Mitigation**: Use `maxWithdraw()` for availability

### 115. Value Leakage via Rounding Direction Errors (Medium)
**Pattern**: Using `previewWithdraw` (rounds up) to calculate amounts transferred out, causing value leakage.

**Vulnerable Code Example** (Strata):
```solidity
function _withdraw(...) internal override {
    if (PreDepositPhase.YieldPhase == currentPhase) {
        assets += previewYield(caller, shares);
        // previewWithdraw rounds UP (against protocol)
        uint sUSDeAssets = sUSDe.previewWithdraw(assets);
        
        // Transfer this rounded UP amount out
        SafeERC20.safeTransfer(IERC20(token), receiver, sUSDeAssets);
    }
}
```

**Impact**: Each redemption leaks value in favor of redeemer at expense of remaining depositors.

**Mitigation**: Use `convertToShares` which rounds down when calculating transfer amounts.

### 116. Share Price Manipulation via Donation During Yield Phase (Critical)
**Pattern**: `totalAssets()` not accounting for direct token transfers, enabling share price manipulation.

**Vulnerable Code Example** (Strata):
```solidity
function totalAssets() public view override returns (uint256) {
    return depositedBase; // Doesn't account for actual sUSDe balance
}

function previewYield(address caller, uint256 shares) public view returns (uint256) {
    uint total_sUSDe = sUSDe.balanceOf(address(this)); // Sees donated balance
    uint total_USDe = sUSDe.previewRedeem(total_sUSDe);
    uint total_yield_USDe = total_USDe - Math.min(total_USDe, depositedBase);
    // Inflated yield due to donations
}
```

**Attack Scenario**:
1. Deposit minimal amount when vault empty
2. Donate large sUSDe amount directly
3. Yield calculations see inflated balance
4. New depositors get fewer shares

**Mitigation**: Include actual token balances in `totalAssets()` during yield phase.

**Cross References**: See also #363 for meta vault variant.

### 117. Minimum Shares Protection Bypass in Multi-Vault (High)
**Pattern**: Alternative withdrawal paths that bypass minimum shares checks.

**Vulnerable Code Example** (Strata):
```solidity
// MetaVault withdrawal doesn't check minimum shares for non-base assets
function _withdraw(address token, ...) internal virtual {
    SafeERC20.safeTransfer(IERC20(token), receiver, tokenAssets);
    onAfterWithdrawalChecks(); // Only checks when withdrawing base asset
}

function onAfterWithdrawalChecks() internal view {
    if (totalSupply() < MIN_SHARES) {
        revert MinSharesViolation();
    }
}
```

**Impact**: First depositor attack protection can be bypassed via meta vault paths.

### 118. Cross-Function Reentrancy in State Updates (Medium)
**Pattern**: State updates split across multiple operations without reentrancy protection.

**Vulnerable Code Example** (Strata):
```solidity
function _deposit(address token, ...) internal virtual {
    depositedBase += baseAssets; // State update 1
    SafeERC20.safeTransferFrom(IERC20(token), caller, address(this), tokenAssets); // External call
    _mint(receiver, shares); // State update 2
}
```

**Impact**: ERC777 tokens or tokens with hooks can reenter between state updates.

### 119. Hardcoded Slippage Parameters (Medium)
**Pattern**: Fixed slippage tolerance that cannot adapt to market conditions.

**Vulnerable Code Example** (Strata):
```solidity
uint256 amountOutMin = (amount * 999) / 1000; // Only 0.1% slippage protection
```

**Impact**: DoS during high volatility or value loss during normal conditions.

### 120. Incorrect Function Routing in Multi-Level Calls (Low)
**Pattern**: Calling wrong function variant in vault hierarchies.

**Vulnerable Code Example** (Strata):
```solidity
function redeem(address token, uint256 shares, address receiver, address owner) public returns (uint256) {
    if (token == asset()) {
        return withdraw(shares, receiver, owner); // Should call redeem, not withdraw
    }
}
```

### 121. Duplicate Vault Array Entries (Low)
**Pattern**: Allowing duplicate entries in tracking arrays causing iteration issues.

**Vulnerable Code Example** (Strata):
```solidity
function addVaultInner(address vaultAddress) internal {
    TAsset memory vault = TAsset(vaultAddress, EAssetType.ERC4626);
    assetsMap[vaultAddress] = vault;
    assetsArr.push(vault); // No duplicate check
}
```

**Impact**: Gas waste, potential DoS, and removal failures.

### 122. Missing Asset Validation in Multi-Vault Systems (Low)
**Pattern**: Not validating that added vaults share the same underlying asset.

**Vulnerable Code Example** (Strata):
```solidity
function addVaultInner(address vaultAddress) internal {
    // No check that IERC4626(vaultAddress).asset() == asset()
    TAsset memory vault = TAsset(vaultAddress, EAssetType.ERC4626);
    assetsMap[vaultAddress] = vault;
}
```

**Impact**: Accounting corruption if vaults with different assets are added.

### 123. Phase Transition State Inconsistencies (Low)
**Pattern**: Removing vault support during phase transitions without clear reasoning.

**Vulnerable Code Example** (Strata):
```solidity
function startYieldPhase() external onlyOwner {
    setYieldPhaseInner();
    redeemMetaVaults(); // Also removes all vault support
    // But vaults can be re-added immediately after
}
```

### 124. EIP-4626 Compliance Violations in View Functions (Low)
**Pattern**: Max functions not accounting for pause states as required by EIP-4626.

**Vulnerable Code Example** (Strata):
```solidity
// Doesn't return 0 when withdrawals disabled as required by EIP-4626
function maxWithdraw(address owner) public view override returns (uint256) {
    return previewRedeem(balanceOf(owner));
    // Should check: if (!withdrawalsEnabled) return 0;
}
```

**Impact**: Integration failures with protocols expecting EIP-4626 compliance.

### 125. Storage Layout Risks in Upgradeable Contracts (Low)
**Pattern**: Upgradeable contracts without proper storage layout protection.

**Vulnerable Code Example** (Strata):
```solidity
abstract contract MetaVault is IMetaVault, PreDepositVault {
    uint256 public depositedBase;
    TAsset[] public assetsArr;
    mapping(address => TAsset) public assetsMap;
    // No storage gaps or ERC7201 namespacing
}
```

**Mitigation**: Use ERC7201 namespaced storage or storage gaps.

### 126. ERC4626 Vault Fee Bypass (Critical)
**Pattern**: Protocol doesn't transfer enough tokens from users to cover ERC4626 vault deposit/withdrawal fees.

**Vulnerable Code Example** (Burve):
```solidity
function addValue(...) external returns (uint256[MAX_TOKENS] memory requiredBalances) {
    // ...
    uint256 realNeeded = AdjustorLib.toReal(token, requiredNominal[i], true);
    requiredBalances[i] = realNeeded;
    TransferHelper.safeTransferFrom(token, msg.sender, address(this), realNeeded);
    Store.vertex(VertexLib.newId(i)).deposit(cid, realNeeded); // Fees charged here!
}
```

**Impact**:
- Users can avoid paying vault fees
- Protocol becomes undercollateralized
- Last users suffer losses when withdrawing

**Cross References**: Related to totalAssets misreporting in #363.

**Mitigation**: Calculate and transfer additional tokens to cover vault fees.

### 127. Adjustor Implementation Reversal (High)
**Pattern**: `toNominal` and `toReal` functions implemented backwards in ERC4626ViewAdjustor.

**Vulnerable Code Example** (Burve):
```solidity
function toNominal(address token, uint256 real, bool) external view returns (uint256 nominal) {
    IERC4626 vault = getVault(token);
    return vault.convertToShares(real); // WRONG: Should use convertToAssets
}

function toReal(address token, uint256 nominal, bool) external view returns (uint256 real) {
    IERC4626 vault = getVault(token);
    return vault.convertToAssets(nominal); // WRONG: Should use convertToShares
}
```

**Impact**: Users deposit more LST tokens than required, causing significant losses.

**Mitigation**: Reverse the implementation of the two functions.

### 128. Netting Logic Error in Vault Withdrawals (High)
**Pattern**: Incorrect netting calculation when both deposits and withdrawals are pending.

**Vulnerable Code Example** (Burve):
```solidity
if (assetsToWithdraw > assetsToDeposit) {
    assetsToDeposit = 0;
    assetsToWithdraw -= assetsToDeposit; // BUG: Subtracting 0!
}
```

**Impact**:
- Withdrawal fees paid on full amount instead of net
- Protocol efficiency loss
- Unnecessary gas costs

**Mitigation**: Subtract before setting to zero.

### 129. Single-Sided Fee Distribution Dilution (High)
**Pattern**: Tax distribution includes new LP in denominator before they should receive rewards.

**Vulnerable Code Example** (Burve):
```solidity
function addValueSingle(...) internal {
    self.valueStaked += value; // Updates state
    self.bgtValueStaked += bgtValue;
    // Tax calculation...
}

// Later in addEarnings:
self.earningsPerValueX128[idx] +=
    (reserveShares << 128) /
    (self.valueStaked - self.bgtValueStaked); // Includes new staker!
```

**Impact**: Existing LPs receive diluted fee share; new LP unfairly receives portion of their own tax.

**Mitigation**: Distribute tax before updating valueStaked.

### 130. Range Re-entry Fee Capture Attack (High)
**Pattern**: Attacker times deposits to capture accumulated fees when ranges come back in range.

**Attack Scenario** (Burve):
1. Burve ranges out of Uniswap V3 range
2. Fees accumulate in unwanted token
3. Attacker deposits right before range re-entry
4. Triggers fee compounding, capturing disproportionate share
5. Immediately withdraws with profit

**Impact**: Fee sniping attack stealing accumulated rewards from legitimate LPs.

**Mitigation**: Add small always-in-range position to ensure continuous fee compounding.

### 131. Fee Bypass in removeValueSingle (High)
**Pattern**: Zero `realTax` calculation due to reading uninitialized variable.

**Vulnerable Code Example** (Burve):
```solidity
function removeValueSingle(...) returns (uint256 removedBalance) {
    // ...
    uint256 realTax = FullMath.mulDiv(
        removedBalance,    // Still 0 here!
        nominalTax,
        removedNominal
    );
}
```

**Impact**: Complete fee bypass on single-token removals.

**Mitigation**: Use `realRemoved` instead of `removedBalance`.

### 132. NoopVault Donation Attack (High)
**Pattern**: Unprotected ERC4626 implementation vulnerable to classic donation attack.

**Attack Path** (Burve):
1. Attacker front-runs first deposit with 1 wei
2. Donates large amount directly to vault
3. Legitimate users receive 0 shares due to rounding
4. Attacker withdraws inflated amount

**Impact**: Complete drainage of user deposits.

**Mitigation**: Implement virtual shares or initial deposit protection.

### 133. Double Withdrawal in removeValueSingle (High)
**Pattern**: Tax not included in vault withdrawal amount, causing insufficient balance.

**Vulnerable Code Example** (Burve):
```solidity
Store.vertex(vid).withdraw(cid, realRemoved, false); // Doesn't include tax
// ...
c.addEarnings(vid, realTax); // Needs tax amount
removedBalance = realRemoved - realTax; // Not enough withdrawn!
```

**Impact**: Function reverts due to insufficient balance.

**Mitigation**: Withdraw `realRemoved + realTax` from vault.

### 134. Reserve Share Overflow Attack (Medium)
**Pattern**: Repeated small trims cause exponential share inflation.

**Vulnerable Code Example** (Burve):
```solidity
shares = (balance == 0)
    ? amount * SHARE_RESOLUTION
    : (amount * reserve.shares[idx]) / balance; // Explodes when balance ≈ 0
```

**Impact**:
- Share counter overflow
- Complete protocol DoS
- Irreversible state corruption

**Mitigation**: Enforce minimum balance thresholds for trimming.

### 135. Admin Parameter Change Front-running (Medium)
**Pattern**: Users can exploit efficiency factor changes without rebalancing.

**Attack Scenario** (Burve):
1. Admin increases efficiency factor `e`
2. Attacker backruns with `removeTokenForValue`
3. Crafts amount so `newTargetX128` equals original
4. Extracts excess tokens meant for reserve

**Impact**: Theft of rebalancing profits.

**Mitigation**: Force rebalancing when changing efficiency factors.

### 136. Missing acceptOwnership in Diamond (Medium)
**Pattern**: Function selector not added for ownership acceptance.

**Vulnerable Code Example** (Burve):
```solidity
adminSelectors[0] = BaseAdminFacet.transferOwnership.selector;
adminSelectors[1] = BaseAdminFacet.owner.selector;
adminSelectors[2] = BaseAdminFacet.adminRights.selector;
// Missing: acceptOwnership.selector
```

**Impact**: Ownership transfers cannot be completed.

**Mitigation**: Add `acceptOwnership` selector to admin facet.

### 137. Protocol Fee Loss During Vault Pause (Medium)
**Pattern**: Protocol fees incorrectly sent to users when vault disables withdrawals.

**Attack Scenario** (Burve):
1. Protocol fees accumulate in diamond
2. Vault temporarily disables withdrawals
3. User collects earnings
4. Withdrawal netting fails
5. Protocol fees transferred to user

**Impact**: Loss of protocol revenue.

**Mitigation**: Revert if vault withdrawals disabled.

### 138. Cross-Closure Value Token Arbitrage (Medium)
**Pattern**: Same ValueToken used across all closures despite different underlying values.

**Attack Path** (Burve):
1. Add liquidity to low-value closure
2. Mint ValueToken
3. Burn ValueToken in high-value closure
4. Withdraw more valuable tokens

**Impact**: Value extraction from legitimate LPs.

**Mitigation**: Use separate ValueTokens per closure.

### 139. Invariant Breaking via Uncapped Growth (Medium)
**Pattern**: Target value can grow beyond designed deMinimus bounds.

**Vulnerable Code Example** (Burve):
```solidity
self.targetX128 += valueX128 / self.n + ((valueX128 % self.n) > 0 ? 1 : 0);
// No check against: |value - target*n| <= deMinimus*n
```

**Impact**: Protocol invariant violation affecting swap pricing.

**Mitigation**: Recalculate target using `ValueLib.t` after additions.

### 140. Earnings Loss in removeValueSingle Ordering (Medium)
**Pattern**: Asset removal before `trimBalance` uses outdated earnings.

**Vulnerable Code Example** (Burve):
```solidity
Store.assets().remove(recipient, cid, value, bgtValue); // Uses old earnings
// ...
(uint256 removedNominal, uint256 nominalTax) = c.removeValueSingle(...);
// Updates earnings after!
```

**Impact**: Users lose >1% of earnings in inactive pools.

**Mitigation**: Call `trimBalance` before asset removal.

### 141. ERC4626 Strategy Return Value Confusion (BakerFi)
**Pattern**: Strategy functions returning shares instead of assets, causing accounting errors.

**Vulnerable Code Example** (BakerFi):
```solidity
// StrategySupplyERC4626
function _deploy(uint256 amount) internal override returns (uint256) {
    return _vault.deposit(amount, address(this)); // Returns shares, not assets!
}

function _undeploy(uint256 amount) internal override returns (uint256) {
    return _vault.withdraw(amount, address(this), address(this)); // Returns shares!
}

function _getBalance() internal view override returns (uint256) {
    return _vault.balanceOf(address(this)); // Returns shares, not assets!
}
```

**Impact**:
- Incorrect share calculations in vault
- Users unable to withdraw full deposits
- Permanent fund lockup

**Mitigation**:
```solidity
function _deploy(uint256 amount) internal override returns (uint256) {
    _vault.deposit(amount, address(this));
    return amount; // Return assets deployed
}

function _getBalance() internal view override returns (uint256) {
    return _vault.convertToAssets(_vault.balanceOf(address(this)));
}
```

### 142. Missing Access Control on Strategy Harvest (BakerFi)
**Pattern**: Anyone can call harvest to manipulate performance fee calculations.

**Vulnerable Code Example** (BakerFi):
```solidity
function harvest() external returns (int256 balanceChange) { // No access control!
    uint256 newBalance = getBalance();
    balanceChange = int256(newBalance) - int256(_deployedAmount);
    _deployedAmount = newBalance; // Updates state
}
```

**Impact**: Users can front-run rebalance calls to avoid performance fees.

**Mitigation**: Add `onlyOwner` modifier to harvest function.

### 143. Deployed Amount Not Updated on Undeploy (BakerFi)
**Pattern**: Strategy's `_deployedAmount` not decremented when assets withdrawn.

**Vulnerable Code Example** (BakerFi):
```solidity
function undeploy(uint256 amount) external returns (uint256) {
    uint256 withdrawalValue = _undeploy(amount);
    ERC20(_asset).safeTransfer(msg.sender, withdrawalValue);
    balance -= amount;
    // _deployedAmount not updated!
    return amount;
}
```

**Impact**:
- Incorrect harvest calculations showing losses
- Performance fees cannot be collected even with profits

**Mitigation**: Update `_deployedAmount` in undeploy function.

### 144. Multi-Strategy Decimal Handling Issues (BakerFi)
**Pattern**: Inconsistent decimal handling between vault (18 decimals) and strategies.

**Vulnerable Code Example** (BakerFi):
```solidity
// Vault assumes 18 decimals for shares
function _depositInternal(uint256 assets, address receiver) returns (uint256 shares) {
    uint256 deployedAmount = _deploy(assets); // May return different decimals
    shares = total.toBase(deployedAmount, false);
}

// Strategy returns native token decimals
function _deploy(uint256 amount) internal returns (uint256) {
    // Returns amount in token's native decimals (e.g., 6 for USDC)
}
```

**Impact**:
- Share calculation errors
- Withdrawal failures
- System incompatible with non-18 decimal tokens

**Mitigation**: Normalize all amounts to 18 decimals or align vault decimals with underlying token.

### 145. Vault Router Permit Vulnerability (BakerFi)
**Pattern**: Permit signatures can be front-run to steal user tokens.

**Vulnerable Code Example** (BakerFi):
```solidity
function pullTokensWithPermit(
    IERC20Permit token,
    uint256 amount,
    address owner,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
) internal virtual {
    IERC20Permit(token).permit(owner, address(this), amount, deadline, v, r, s);
    IERC20(address(token)).safeTransferFrom(owner, address(this), amount);
}
```

**Attack Scenario**:
1. User submits transaction with permit signature
2. Attacker sees it in mempool, extracts signature
3. Attacker calls router with user's signature
4. Attacker then calls `sweepTokens` to steal funds

**Impact**: Complete theft of user funds.

**Mitigation**: Remove permit functionality from router or implement nonce tracking.

### 146. Vault Router Allowance Exploitation (BakerFi)
**Pattern**: Anyone can drain approved tokens through router commands.

**Vulnerable Code Example** (BakerFi):
```solidity
// Commands allow arbitrary token movements
function pullTokenFrom(IERC20 token, address from, uint256 amount) internal {
    if (token.allowance(from, address(this)) < amount) revert NotEnoughAllowance();
    IERC20(token).safeTransferFrom(from, address(this), amount);
}

function pushTokenFrom(IERC20 token, address from, address to, uint256 amount) internal {
    if (token.allowance(from, address(this)) < amount) revert NotEnoughAllowance();
    IERC20(token).safeTransferFrom(from, to, amount);
}
```

**Impact**: Complete drainage of user funds if they approved router.

**Mitigation**: Restrict these commands to `msg.sender == from`.

### 147. ERC4626 Vault Operations Owner Bypass (BakerFi)
**Pattern**: Router allows anyone to redeem/withdraw other users' vault shares.

**Vulnerable Code Example** (BakerFi):
```solidity
function _handleVaultRedeem(bytes calldata data, ...) private returns (bytes memory) {
    IERC4626 vault;
    uint256 shares;
    address receiver;
    address owner;
    assembly {
        vault := calldataload(data.offset)
        shares := calldataload(add(data.offset, 0x20))
        receiver := calldataload(add(data.offset, 0x40))
        owner := calldataload(add(data.offset, 0x60)) // User-controlled!
    }
    uint256 assets = redeemVault(vault, shares, receiver, owner);
}
```

**Impact**: Anyone can steal vault shares by specifying victim as owner.

**Mitigation**: Force `owner = msg.sender` for vault operations.

### 148. Non-ERC4626 Compliant View Functions (BakerFi)
**Pattern**: View functions not following ERC4626 specifications.

**Issues**:
- `maxDeposit`/`maxMint` always return `type(uint256).max` ignoring limits
- Don't return 0 when paused
- `previewMint` rounds down instead of up
- `previewWithdraw` doesn't include fees and rounds down
- `previewRedeem` doesn't account for withdrawal fees

**Impact**: Integration failures with protocols expecting ERC4626 compliance.

**Mitigation**: Implement view functions according to ERC4626 specification.

### 149. Multi-Strategy New Strategy DoS (BakerFi)
**Pattern**: New strategies added without approval cause deposit/withdrawal failures.

**Vulnerable Code Example** (BakerFi):
```solidity
function addStrategy(IStrategy strategy) external onlyRole(VAULT_MANAGER_ROLE) {
    _strategies.push(strategy);
    _weights.push(0);
    // No approval given to strategy!
}
```

**Impact**: Vault operations fail when trying to deploy to unapproved strategy.

**Mitigation**: Approve strategy with max allowance when adding.

### 150. Leverage Strategy Removal Accounting Error (BakerFi)
**Pattern**: Removing leverage strategies fails due to incorrect received amount assumptions.

**Vulnerable Code Example** (BakerFi):
```solidity
function removeStrategy(uint256 index) external {
    uint256 strategyAssets = _strategies[index].totalAssets();
    if (strategyAssets > 0) {
        IStrategy(_strategies[index]).undeploy(strategyAssets);
        _allocateAssets(strategyAssets); // Assumes full amount received!
    }
}
```

**Impact**: Transaction reverts as leverage strategies return less than requested.

**Mitigation**: Use actual returned amount for allocation.

### 151. Vault Unusable with Direct Strategy Transfers (BakerFi)
**Pattern**: Direct token transfers to strategy make vault permanently unusable.

**Vulnerable Code Example** (BakerFi):
```solidity
function _depositInternal(uint256 assets, address receiver) returns (uint256 shares) {
    Rebase memory total = Rebase(totalAssets(), totalSupply());
    // Reverts if totalAssets > 0 but totalSupply == 0
    if (!((total.elastic == 0 && total.base == 0) || (total.base > 0 && total.elastic > 0))) {
        revert InvalidAssetsState();
    }
}
```

**Attack**: Send tokens directly to strategy before first deposit.

**Impact**: Permanent DoS of vault.

**Mitigation**: Add recovery mechanism for edge cases.

### 152. Deposit Limit Bypass Through Recipients (BakerFi)
**Pattern**: Max deposit limit only checks msg.sender, not recipient.

**Vulnerable Code Example** (BakerFi):
```solidity
function _depositInternal(uint256 assets, address receiver) returns (uint256 shares) {
    uint256 maxDepositLocal = getMaxDeposit();
    if (maxDepositLocal > 0) {
        uint256 depositInAssets = (balanceOf(msg.sender) * _ONE) / tokenPerAsset();
        // Only checks msg.sender, not receiver!
        if (newBalance > maxDepositLocal) revert MaxDepositReached();
    }
    _mint(receiver, shares);
}
```

**Impact**: Unlimited deposits by using different recipient addresses.

**Mitigation**: Track deposits by actual depositor in mapping.

### 153. Rebalance Not Paused with Vault (BakerFi)
**Pattern**: Rebalance remains callable when vault is paused.

**Vulnerable Code Example** (BakerFi):
```solidity
function rebalance(IVault.RebalanceCommand[] calldata commands)
    external nonReentrant onlyRole(VAULT_MANAGER_ROLE) { // No whenNotPaused!
    // Can collect performance fees while users can't withdraw
}
```

**Impact**: Performance fees collected while users locked out.

**Mitigation**: Add `whenNotPaused` modifier to rebalance.

### 154. Router Deposit Limit DoS (BakerFi)
**Pattern**: VaultRouter itself subject to deposit limits as msg.sender.

**Vulnerable Code Example** (BakerFi):
```solidity
// In vault:
if (maxDepositLocal > 0) {
    uint256 depositInAssets = (balanceOf(msg.sender) * _ONE) / tokenPerAsset();
    // msg.sender is VaultRouter!
}
```

**Attack**: Deposit through router until router hits limit, blocking all router deposits.

**Impact**: Complete DoS of router deposit functionality.

**Mitigation**: Exempt router from limits or track actual depositor.

### 155. Zero Amount Strategy Undeploy DoS (BakerFi)
**Pattern**: Strategies with no assets cause withdrawal DoS in multi-strategy vaults.

**Vulnerable Code Example** (BakerFi):
```solidity
function _deallocateAssets(uint256 amount) internal returns (uint256 totalUndeployed) {
    for (uint256 i = 0; i < strategiesLength; i++) {
        uint256 fractAmount = (amount * currentAssets[i]) / totalAssets;
        totalUndeployed += IStrategy(_strategies[i]).undeploy(fractAmount); // Reverts if 0!
    }
}
```

**Impact**: All withdrawals blocked if any strategy has zero assets.

**Mitigation**: Skip strategies with zero undeploy amounts.

### 156. Morpho Strategy Interest Calculation Error (BakerFi)
**Pattern**: `assetsMax` calculation missing accrued interest in undeploy.

**Vulnerable Code Example** (BakerFi):
```solidity
function _undeploy(uint256 amount) internal override returns (uint256) {
    uint256 totalSupplyAssets = _morpho.totalSupplyAssets(id); // Stale!
    uint256 totalSupplyShares = _morpho.totalSupplyShares(id);
    uint256 assetsMax = shares.toAssetsDown(totalSupplyAssets, totalSupplyShares);
    // But amount includes interest from expectedSupplyAssets!
}
```

**Impact**: Incorrect branch selection leading to user receiving extra funds.

**Mitigation**: Use `expectedSupplyAssets` for `assetsMax` calculation.

### 157. Paused Third-Party Strategy Lock (BakerFi)
**Pattern**: No way to handle paused third-party protocols in multi-strategy vaults.

**Vulnerable Code Example** (BakerFi):
```solidity
// All operations attempt to interact with all strategies
function _deallocateAssets(uint256 amount) internal {
    for (uint256 i = 0; i < strategiesLength; i++) {
        // Reverts if strategy's underlying protocol is paused
        totalUndeployed += IStrategy(_strategies[i]).undeploy(fractAmount);
    }
}
```

**Impact**: Single paused protocol locks entire multi-strategy vault.

**Mitigation**: Add emergency exclusion mechanism for paused strategies.

### 158. Last Strategy Removal Division by Zero (BakerFi)
**Pattern**: Removing last strategy causes division by zero.

**Vulnerable Code Example** (BakerFi):
```solidity
function removeStrategy(uint256 index) external {
    _totalWeight -= _weights[index];
    _weights[index] = 0; // Now _totalWeight = 0
    if (strategyAssets > 0) {
        IStrategy(_strategies[index]).undeploy(strategyAssets);
        _allocateAssets(strategyAssets); // Division by _totalWeight = 0!
    }
}
```

**Impact**: Cannot remove last strategy if it has assets.

**Mitigation**: Handle last strategy removal specially or prevent it.

### 159. Wrong Token Configuration in Morpho Strategy (BakerFi)
**Pattern**: Allowing mismatched asset and loan tokens in Morpho markets.

**Vulnerable Code Example** (BakerFi):
```solidity
constructor(address asset_, address morphoBlue, Id morphoMarketId) {
    _asset = asset_; // Can be different from market's loanToken!
    _marketParams = _morpho.idToMarketParams(morphoMarketId);
    if (!ERC20(asset_).approve(morphoBlue, type(uint256).max)) {
        // Approves wrong token!
    }
}
```

**Impact**: Strategy completely unusable due to token mismatch.

**Mitigation**: Validate `asset_ == _marketParams.loanToken`.

### 160. Strategy Undeploy Return Value Mismatch (BakerFi)
**Pattern**: Strategy returns requested amount instead of actual withdrawn amount.

**Vulnerable Code Example** (BakerFi):
```solidity
function undeploy(uint256 amount) external returns (uint256 undeployedAmount) {
    uint256 withdrawalValue = _undeploy(amount); // Actual amount
    ERC20(_asset).safeTransfer(msg.sender, withdrawalValue);
    return amount; // WRONG: Should return withdrawalValue!
}
```

**Impact**: Vault receives wrong amount, causing transfer failures.

**Mitigation**: Return actual withdrawn amount.

### 161. Non-Whitelisted Recipient Bypass (BakerFi)
**Pattern**: Whitelist restrictions only check caller, not recipient.

**Vulnerable Code Example** (BakerFi):
```solidity
function deposit(uint256 assets, address receiver) public override onlyWhiteListed {
    // Only checks if msg.sender is whitelisted
    // receiver can be anyone!
    return _depositInternal(assets, receiver);
}
```

**Impact**: Non-whitelisted users can receive shares and withdraw through router.

**Mitigation**: Check both caller and receiver are whitelisted.

### 162. Dispatch Command Parsing Error (BakerFi)
**Pattern**: Wrong variable used for PULL_TOKEN command check.

**Vulnerable Code Example** (BakerFi):
```solidity
} else if (action == Commands.PULL_TOKEN) { // Should be actionToExecute!
    output = _handlePullToken(data, callStack, inputMapping);
}
```

**Impact**: PULL_TOKEN with input mapping causes revert.

**Mitigation**: Use `actionToExecute` instead of `action`.

### 163. Reward Calculation Fee Bypass (LoopFi)
**Pattern**: Reward fees not deducted from user amount, causing DoS or fund theft.

**Vulnerable Code Example** (LoopFi):
```solidity
function claim(uint256[] memory amounts, uint256 maxAmountIn) external returns (uint256 amountIn) {
    // Distribute BAL rewards
    IERC20(BAL).safeTransfer(_config.lockerRewards, (amounts[0] * _config.lockerIncentive) / INCENTIVE_BASIS);
    IERC20(BAL).safeTransfer(msg.sender, amounts[0]); // Full amount sent, fee not deducted!
}
```

**Impact**:
- DoS when contract has insufficient rewards
- Users receive extra rewards, stealing from others

**Mitigation**: Deduct fees before sending to user.

### 164. Liquidation Penalty Not Applied to Collateral (LoopFi)
**Pattern**: Liquidators receive full collateral value despite penalty mechanism.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePosition(address owner, uint256 repayAmount) external {
    uint256 takeCollateral = wdiv(repayAmount, discountedPrice);
    uint256 deltaDebt = wmul(repayAmount, liqConfig_.liquidationPenalty);
    uint256 penalty = wmul(repayAmount, WAD - liqConfig_.liquidationPenalty);
    // Collateral calculation doesn't consider penalty!
}
```

**Impact**: Self-liquidation profitability despite penalty mechanism.

**Mitigation**: Apply penalty to collateral amount calculation.

### 165. Zero Rate Quota Interest Bypass (LoopFi)
**Pattern**: New quota tokens have zero rates, allowing interest-free borrowing.

**Vulnerable Code Example** (LoopFi):
```solidity
function addQuotaToken(address token) external override gaugeOnly {
    quotaTokensSet.add(token); // rates are 0 by default
    totalQuotaParams[token].cumulativeIndexLU = 1;
    emit AddQuotaToken(token);
}
```

**Impact**: Users can borrow at zero interest until rates are updated.

**Mitigation**: Set initial rates when adding quota tokens.

### 166. Missing Role Setup in Access Control (LoopFi)
**Pattern**: AccessControl roles never initialized, causing permanent DoS.

**Vulnerable Code Example** (LoopFi):
```solidity
contract AuraVault inherits AccessControl {
    // Constructor doesn't call _setupRole()
    // No roles can ever be granted!
}
```

**Impact**:
- Config functions permanently inaccessible
- Claim function always reverts (sends to address(0))

**Mitigation**: Initialize roles in constructor.

### 167. Share/Asset Confusion in Vault Redeem (LoopFi)
**Pattern**: Using shares as assets in reward pool operations.

**Vulnerable Code Example** (LoopFi):
```solidity
function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
    uint256 assets = IPool(rewardPool).redeem(shares, address(this), address(this));
    // rewardPool expects assets, not shares!
}
```

**Impact**: Users receive less assets than entitled.

**Mitigation**: Convert shares to assets before calling rewardPool.

### 168. Front-Running Liquidation DoS (LoopFi)
**Pattern**: Borrowers can front-run liquidations with minimal repayments.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePosition(address owner, uint256 repayAmount) external {
    // If debt < repayAmount, calcDecrease underflows
    (newDebt, ...) = calcDecrease(deltaDebt, debtData.debt, ...);
}
```

**Attack**: Repay 1 wei before liquidation to cause underflow.

**Impact**: Liquidations permanently blocked.

**Mitigation**: Handle case where repayAmount > current debt.

### 169. Interest Rate Manipulation Through Cycles (LoopFi)
**Pattern**: Rapid borrow-repay cycles compound interest rates.

**Vulnerable Code Example** (LoopFi):
```solidity
function _updateBaseInterest(...) internal {
    if (block.timestamp != lastBaseInterestUpdate_) {
        _baseInterestIndexLU = _calcBaseInterestIndex(lastBaseInterestUpdate_).toUint128();
        // Compounds on every update!
    }
}
```

**Impact**: Higher interest rates for all borrowers without risk to attacker.

**Mitigation**: Add borrowing fees or minimum loan duration.

### 170. Reward Overwrite in vestTokens (LoopFi)
**Pattern**: Missing state update causes previous rewards to be erased.

**Vulnerable Code Example** (LoopFi):
```solidity
function vestTokens(address user, uint256 amount, bool withPenalty) external {
    if (user == address(this)) {
        _notifyReward(address(rdntToken), amount); // Missing _updateReward!
        return;
    }
}
```

**Impact**: Users lose all previously accumulated rewards.

**Mitigation**: Call `_updateReward` before `_notifyReward`.

### 171. Position Increase During Liquidation (LoopFi)
**Pattern**: Missing position address in decrease lever operations.

**Vulnerable Code Example** (LoopFi):
```solidity
function _onDecreaseLever(LeverParams memory leverParams, uint256 subCollateral) internal returns (uint256) {
    uint256 withdrawnCollateral = ICDPVault(leverParams.vault).withdraw(address(this), subCollateral);
    // Should withdraw from leverParams.position!
}
```

**Impact**: Decrease lever operations always revert.

**Mitigation**: Use correct position address for withdrawals.

### 172. Interest Calculation Mismatch (LoopFi)
**Pattern**: Pool uses simple interest while positions use compound interest.

**Vulnerable Code Example** (LoopFi):
```solidity
// Pool: borrowed * rate * time
function _calcBaseInterestAccrued(uint256 timestamp) private view returns (uint256) {
    return (_totalDebt.borrowed * baseInterestRate().calcLinearGrowth(timestamp)) / RAY;
}

// Position: Compounds through index updates
function _calcBaseInterestIndex(uint256 timestamp) private view returns (uint256) {
    return (_baseInterestIndexLU * (RAY + baseInterestRate().calcLinearGrowth(timestamp))) / RAY;
}
```

**Impact**:
- Borrowers pay more than expected
- Protocol accounting inconsistencies
- Final withdrawals may revert

**Mitigation**: Align interest calculation methods.

### 173. Liquidation Debt Precision Loss (LoopFi)
**Pattern**: Full debt liquidation nearly impossible due to timing.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePosition(address owner, uint256 repayAmount) external {
    if (deltaDebt == maxRepayment) {
        // Must be exact to the second!
        newDebt = 0;
    } else {
        // Reverts if deltaDebt > maxRepayment
    }
}
```

**Impact**: Bad debt accumulation over time.

**Mitigation**: Allow slight overpayment with refund mechanism.

### 174. Bad Debt Interest Loss (LoopFi)
**Pattern**: Interest not credited to LPs during bad debt liquidation.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePositionBadDebt(address owner, uint256 repayAmount) external {
    pool.repayCreditAccount(debtData.debt, 0, loss); // profit = 0!
    // debtData.accruedInterest is lost
}
```

**Impact**: LP stakers lose accrued interest on bad debt positions.

**Mitigation**: Include accrued interest as profit parameter.

### 175. Flash Loan Fee Accounting Error (LoopFi)
**Pattern**: Flash loan fees incorrectly handled as debt repayment.

**Vulnerable Code Example** (LoopFi):
```solidity
function flashLoan(...) external returns (bool) {
    pool.repayCreditAccount(total - fee, fee, 0);
    // Should use mintProfit() for fees!
}
```

**Impact**: WETH locked in pool, withdrawal failures.

**Mitigation**: Use `mintProfit()` for flash loan fees.

### 176. Infinite Loop in Withdraw (LoopFi)
**Pattern**: Loop counter not incremented on zero amounts.

**Vulnerable Code Example** (LoopFi):
```solidity
for (i = 0; ; ) {
    uint256 earnedAmount = _userEarnings[_address][i].amount;
    if (earnedAmount == 0) continue; // i never incremented!
}
```

**Impact**: Withdrawal permanently blocked.

**Mitigation**: Increment counter before continue.

### 177. Reward Distribution Griefing (LoopFi)
**Pattern**: Dust amounts reset reward distribution periods.

**Vulnerable Code Example** (LoopFi):
```solidity
function _notifyUnseenReward(address token) internal {
    uint256 unseen = IERC20(token).balanceOf(address(this)) - r.balance;
    if (unseen > 0) {
        _notifyReward(token, unseen); // Even 1 wei resets!
    }
}
```

**Attack**: Send 1 wei repeatedly to extend vesting periods.

**Impact**: Legitimate rewards delayed indefinitely.

**Mitigation**: Implement minimum reward thresholds.

### 178. CDP Liquidation Manipulation via Partial Liquidations (LoopFi)
**Pattern**: Partial liquidations can temporarily make unsafe positions safe, delaying necessary full liquidations.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePosition(address owner, uint256 repayAmount) external whenNotPaused {
    // ... (validation and state loading)
    if (_isCollateralized(calcTotalDebt(debtData), wmul(position.collateral, spotPrice_), config.liquidationRatio))
        revert CDPVault__liquidatePosition_notUnsafe();
    // ... (liquidation calculations)
    position = _modifyPosition(owner, position, newDebt, newCumulativeIndex, -toInt256(takeCollateral), totalDebt);
    // Position can become temporarily safe after partial liquidation
}
```

**Impact**:
- Self-liquidation can protect positions from full liquidation
- Protocol losses increase if collateral continues to fall
- Goes against intended liquidation mechanics

**Mitigation**: Flag positions as unsafe once they cross the threshold, only unflag on collateral deposits.

### 179. Wrong Amount Used in Position Repayments (LoopFi)
**Pattern**: Using user-specified amount instead of actual swapped amount in position actions.

**Vulnerable Code Example** (LoopFi):
```solidity
function _repay(address vault, address position, CreditParams calldata creditParams, PermitParams calldata permitParams) internal {
    uint256 amount = creditParams.amount;
    if (creditParams.auxSwap.assetIn != address(0)) {
        amount = _transferAndSwap(creditParams.creditor, creditParams.auxSwap, permitParams);
        // amount is now the swapped amount
    }
    // ... but still uses creditParams.amount!
    ICDPVault(vault).modifyCollateralAndDebt(position, address(this), address(this), 0, -toInt256(creditParams.amount));
}
```

**Impact**: Transactions revert due to insufficient balance when swap returns different amount.

**Mitigation**: Use the actual swapped amount for vault operations.

### 180. Swap Token Calculation Error for EXACT_OUT (LoopFi)
**Pattern**: Always returning last asset for Balancer swaps regardless of swap type.

**Vulnerable Code Example** (LoopFi):
```solidity
function getSwapToken(SwapParams memory swapParams) public pure returns (address token) {
    if (swapParams.swapProtocol == SwapProtocol.BALANCER) {
        (, address[] memory primarySwapPath) = abi.decode(swapParams.args, (bytes32, address[]));
        token = primarySwapPath[primarySwapPath.length - 1]; // Wrong for EXACT_OUT!
    }
}
```

**Impact**: Wrong token identification for EXACT_OUT swaps where assets are in reverse order.

**Mitigation**: Check swap type and return appropriate token:
```solidity
if (swapParams.swapType == SwapType.EXACT_OUT) token = primarySwapPath[0];
else token = primarySwapPath[primarySwapPath.length - 1];
```

### 181. Hardcoded Inflation Protection Time (LoopFi)
**Pattern**: Using hardcoded timestamp instead of relative time for reward distribution.

**Vulnerable Code Example** (LoopFi):
```solidity
uint256 private constant INFLATION_PROTECTION_TIME = 1749120350; // Fixed timestamp!

function claim(uint256[] memory amounts, uint256 maxAmountIn) external returns (uint256 amountIn) {
    // ...
    if (block.timestamp <= INFLATION_PROTECTION_TIME) {
        IERC20(AURA).safeTransfer(_config.lockerRewards, (amounts[1] * _config.lockerIncentive) / INCENTIVE_BASIS);
        IERC20(AURA).safeTransfer(msg.sender, amounts[1]);
    }
}
```

**Impact**: Reward distribution window shrinks with each passing day; if deployed too late, no AURA rewards distributed.

**Mitigation**: Set protection time in constructor:
```solidity
uint256 private immutable INFLATION_PROTECTION_TIME;
constructor(...) {
    INFLATION_PROTECTION_TIME = block.timestamp + 365 days;
}
```

### 182. Position Action Lever Functions Always Fail (LoopFi)
**Pattern**: Depositing collateral twice in the same transaction causing reverts.

**Vulnerable Code Example** (LoopFi):
```solidity
function _onIncreaseLever(LeverParams memory leverParams, uint256 upFrontAmount, uint256 addCollateralAmount)
    internal override returns (uint256) {
    // First deposit
    return ICDPVault(leverParams.vault).deposit(address(this), addCollateralAmount);
}

// Later in onFlashLoan:
ICDPVault(leverParams.vault).modifyCollateralAndDebt(
    leverParams.position,
    address(this),
    address(this),
    toInt256(collateral), // Tries to deposit AGAIN!
    toInt256(addDebt)
);
```

**Impact**: increaseLever functionality completely broken for ERC4626 positions.

**Mitigation**: Return amount instead of depositing in `_onIncreaseLever`.

### 183. Pool Action Join Parameters Corruption (LoopFi)
**Pattern**: Incorrect array indexing when updating Balancer pool join parameters.

**Vulnerable Code Example** (LoopFi):
```solidity
function updateLeverJoin(...) external view returns (PoolActionParams memory outParams) {
    // ...
    for (uint256 i = 0; i < len; ) {
        uint256 assetIndex = i - (skipIndex ? 1 : 0);
        if (assets[i] == joinToken) {
            maxAmountsIn[i] = joinAmount;
            assetsIn[assetIndex] = joinAmount; // Wrong index if BPT not found!
        }
        // ...
    }
}
```

**Impact**: Balancer joins fail due to mismatched array indices between assets and amounts.

**Mitigation**: Properly identify pool token from Balancer vault before processing.

### 184. Wrong Collateral Amount in Decrease Lever (LoopFi)
**Pattern**: Updating wrong token amount as collateral withdrawn from vault.

**Vulnerable Code Example** (LoopFi):
```solidity
function _onDecreaseLever(LeverParams memory leverParams, uint256 subCollateral)
    internal override returns (uint256 tokenOut) {
    uint256 withdrawnCollateral = ICDPVault(leverParams.vault).withdraw(address(this), subCollateral);
    tokenOut = IERC4626(leverParams.collateralToken).redeem(withdrawnCollateral, address(this), address(this));
    
    if (leverParams.auxAction.args.length != 0) {
        bytes memory exitData = _delegateCall(address(poolAction),
            abi.encodeWithSelector(poolAction.exit.selector, leverParams.auxAction));
        tokenOut = abi.decode(exitData, (uint256)); // Updates with pool exit amount!
    }
}
```

**Impact**: Wrong amount sent to users, funds stuck in contract.

**Mitigation**: Track actual token balance instead of relying on return values.

### 185. Balancer Exit Returns Wrong Amount (LoopFi)
**Pattern**: Returning recipient's total balance instead of amount received from exit.

**Vulnerable Code Example** (LoopFi):
```solidity
function _balancerExit(PoolActionParams memory poolActionParams) internal returns (uint256 retAmount) {
    // ... perform exit ...
    return IERC20(assets[outIndex]).balanceOf(address(poolActionParams.recipient)); // Total balance!
}
```

**Impact**: Inflated return values cause transaction reverts when contract tries to send more than received.

**Mitigation**: Calculate balance difference before and after exit.

### 186. Deprecated Chainlink Function Usage (LoopFi)
**Pattern**: Using deprecated `answeredInRound` which Chainlink no longer supports.

**Vulnerable Code Example** (LoopFi):
```solidity
function _fetchAndValidate(address priceFeed) private view returns (uint256 answer) {
    (, int256 _answer, , uint256 updatedAt, uint80 answeredInRound) = AggregatorV3Interface(priceFeed)
        .latestRoundData();
    // answeredInRound is deprecated!
}
```

**Impact**: Potential incorrect price validation or future breaking changes.

**Mitigation**: Remove usage of `answeredInRound`.

### 187. Minimum Shares Griefing Attack (LoopFi)
**Pattern**: Attacker can force users to leave funds locked or DoS deposits.

**Vulnerable Code Example** (LoopFi):
```solidity
function _checkMinShares() internal view {
    uint256 _totalSupply = totalSupply();
    if(_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
}
```

**Attack Scenarios**:
1. Deposit 1 wei after each user to block full withdrawals
2. Transfer small amount to contract to make deposits require huge amounts

**Impact**: Last withdrawer loses MIN_SHARES worth of funds or deposits blocked.

**Mitigation**: Protocol should fund initial shares and remove check.

### 188. Token Scale Not Applied in Liquidations (LoopFi)
**Pattern**: Sending internal amount instead of scaled amount to liquidators.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePosition(address owner, uint256 repayAmount) external {
    // ... calculate takeCollateral (internal amount) ...
    token.safeTransfer(msg.sender, takeCollateral); // Should scale by tokenScale!
}

// Compare to withdraw:
function withdraw(address to, uint256 amount) external {
    uint256 amount = wmul(abs(deltaCollateral), tokenScale); // Scales properly
    token.safeTransfer(collateralizer, amount);
}
```

**Impact**: Liquidators receive 100x more tokens than intended for 16-decimal tokens.

**Mitigation**: Apply tokenScale before transfer: `wmul(takeCollateral, tokenScale)`.

### 189. Missing Slippage Protection in Vault Operations (LoopFi)
**Pattern**: No minimum shares/assets parameters in deposit/mint functions.

**Vulnerable Code Example** (LoopFi):
```solidity
function deposit(uint256 assets, address receiver) public virtual override returns (uint256) {
    uint256 shares = previewDeposit(assets);
    _deposit(_msgSender(), receiver, assets, shares);
    // No check that shares >= minShares!
}
```

**Impact**: Users vulnerable to sandwich attacks receiving fewer shares than expected.

**Mitigation**: Add slippage parameters:
```solidity
function deposit(uint256 assets, uint256 minShares, address receiver) public virtual override returns (uint256) {
    uint256 shares = previewDeposit(assets);
    require(shares >= minShares, "Insufficient shares");
    // ...
}
```

### 190. Permit DoS via Front-Running (LoopFi)
**Pattern**: Attacker can extract permit signature and use it first.

**Vulnerable Code Example** (LoopFi):
```solidity
function _transferFrom(address token, address from, address to, uint256 amount, PermitParams memory params) internal {
    if (params.approvalType == ApprovalType.PERMIT) {
        IERC20Permit(token).safePermit(from, to, params.approvalAmount, params.deadline, params.v, params.r, params.s);
        IERC20(token).safeTransferFrom(from, to, amount);
    }
}
```

**Attack**: Front-run with same permit parameters, causing original transaction to fail due to nonce increment.

**Impact**: DoS of permit-based transfers.

**Mitigation**: Use try-catch and check existing allowance as fallback.

### 191. Pause Mechanism Bypass (LoopFi)
**Pattern**: Users can bypass pause by calling underlying functions directly.

**Vulnerable Code Example** (LoopFi):
```solidity
function deposit(address to, uint256 amount) external whenNotPaused returns (uint256 tokenAmount) {
    tokenAmount = wdiv(amount, tokenScale);
    int256 deltaCollateral = toInt256(tokenAmount);
    modifyCollateralAndDebt({...}); // This is public!
}

function modifyCollateralAndDebt(...) public { // No whenNotPaused!
    // Users can call this directly
}
```

**Impact**: Pause mechanism ineffective for protecting protocol.

**Mitigation**: Add `whenNotPaused` to all state-changing functions.

### 192. Incorrect Loss Calculation in Bad Debt (LoopFi)
**Pattern**: Including interest in loss calculation when it was never received.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePositionBadDebt(address owner, uint256 repayAmount) external {
    // ...
    uint256 loss = calcTotalDebt(debtData) - repayAmount; // Includes accruedInterest!
    pool.repayCreditAccount(debtData.debt, 0, loss);
}

function calcTotalDebt(DebtData memory debtData) internal pure returns (uint256) {
    return debtData.debt + debtData.accruedInterest; // Interest is profit, not principal
}
```

**Impact**: Protocol burns extra treasury shares representing "lost" profit that was never earned.

**Mitigation**: Calculate loss as `debtData.debt - repayAmount`.

### 193. Flash Loan Fee Bypass (LoopFi)
**Pattern**: Not accounting for protocol fees in flash loan calculations.

**Vulnerable Code Example** (LoopFi):
```solidity
function decreaseLever(LeverParams memory leverParams) external onlyOwner(leverParams.position) {
    uint256 fee = flashlender.flashFee(leverParams.singleSwap.tokenIn, leverParams.primarySwap.amount);
    uint256 loanAmount = leverParams.primarySwap.amount - fee; // Should add fee!
    // ...
}
```

**Impact**: Insufficient funds to repay flash loan when protocol fee > 0.

**Mitigation**: Calculate as `loanAmount = leverParams.primarySwap.amount - fee` and adjust debt reduction accordingly.

### 194. Loss Not Applied to Pool State (LoopFi)
**Pattern**: Bad debt interest loss not reflected in pool accounting.

**Vulnerable Code Example** (LoopFi):
```solidity
function liquidatePositionBadDebt(address owner, uint256 repayAmount) external {
    // ...
    pool.repayCreditAccount(debtData.debt, 0, loss); // profit = 0, but should include interest
}
```

**Impact**: LPs don't receive accrued interest from bad debt positions.

**Mitigation**: Pass accrued interest as profit parameter.

### 195. Rewards Overwrite via Vesting (LoopFi)
**Pattern**: Anyone can grief users by vesting minimal rewards daily.

**Vulnerable Code Example** (LoopFi):
```solidity
function claim(address onBehalfOf) external {
    uint256 reward = _allPendingRewards[onBehalfOf];
    // Anyone can call this!
    rdntToken_.safeTransfer(address(mfd), reward);
    IMFDPlus(mfd).vestTokens(onBehalfOf, reward, false);
}

// In MultiFeeDistribution:
function vestTokens(address user, uint256 amount, bool withPenalty) external {
    // Creates new entry in _userEarnings array
    // Maximum one entry per day, but anyone can create it
}
```

**Impact**: Array grows to cause DoS when user tries to withdraw after vesting period.

**Mitigation**: Add access control to prevent griefing or allow batch withdrawals.

### 196. Position Action Token Return Scale Errors (LoopFi)
**Pattern**: Position action functions returning amounts in wrong decimal scale.

**Vulnerable Code Example** (LoopFi):
```solidity
function _onWithdraw(address vault, address position, address /*dst*/, uint256 amount)
    internal override returns (uint256) {
    return ICDPVault(vault).withdraw(position, amount); // Returns WAD scale
}

// But caller expects token scale:
function _withdraw(...) internal returns (uint256) {
    uint256 collateral = _onWithdraw(...); // Gets WAD
    IERC20(collateralParams.targetToken).safeTransfer(
        collateralParams.collateralizer,
        collateral // Uses WAD amount for token transfer!
    );
}
```

**Impact**: Withdrawals fail for non-18 decimal tokens due to insufficient balance.

**Mitigation**: Convert return values to proper scale.

### 197. Reward Pool Eligibility Check Race Condition (LoopFi)
**Pattern**: Eligibility checked before refresh, allowing ineligible users to claim.

**Vulnerable Code Example** (LoopFi):
```solidity
function claim(address _user, address[] memory _tokens) public whenNotPaused {
    if (eligibilityMode != EligibilityModes.DISABLED) {
        if (!eligibleDataProvider.isEligibleForRewards(_user)) revert EligibleRequired();
        checkAndProcessEligibility(_user, true, true); // Refresh happens after check!
    }
}
```

**Impact**: Users who lost eligibility due to price changes can still claim rewards.

**Mitigation**: Call `checkAndProcessEligibility` before eligibility check.

### 198. Manual Emissions Stop Balance Sync Issues (LoopFi)
**Pattern**: Setting balances to zero breaks subsequent eligibility updates.

**Vulnerable Code Example** (LoopFi):
```solidity
function manualStopEmissionsFor(address _user, address[] memory _tokens) public isWhitelisted {
    // Sets all balances to 0
    user.amount = 0;
    user.rewardDebt = 0;
    pool.totalSupply = newTotalSupply;
}

// Later when user becomes eligible:
function handleActionAfter(address _user, uint256 _balance, uint256 _totalSupply) external {
    if (isCurrentlyEligible && lastEligibleStatus) {
        _handleActionAfterForToken(msg.sender, _user, _balance, _totalSupply);
        // Only updates one vault, others remain at 0!
    }
}
```

**Impact**: User only earns rewards on one vault after re-gaining eligibility.

**Mitigation**: Update all vault balances when eligibility status changes.

### 199. Reward Time Calculation Discrepancies (LoopFi)
**Pattern**: Pool update timestamps can diverge from mass update timestamps.

**Vulnerable Code Example** (LoopFi):
```solidity
function _updatePool(VaultInfo storage pool, uint256 _totalAllocPoint) internal {
    uint256 timestamp = block.timestamp;
    uint256 endReward = endRewardTime();
    if (endReward <= timestamp) {
        timestamp = endReward; // Pool timestamp < lastAllPoolUpdate
    }
    pool.lastRewardTime = timestamp;
}

// Later:
function endRewardTime() public returns (uint256) {
    uint256 newEndTime = (unclaimedRewards + extra) / rewardsPerSecond + lastAllPoolUpdate;
    // Uses lastAllPoolUpdate which can be > pool timestamps
}
```

**Impact**: Pools can claim rewards beyond depletion time.

**Mitigation**: Synchronize timestamps or adjust endTime calculation.

### 200. Deposit Auxiliary Swap Validation Error (LoopFi)
**Pattern**: Incorrect validation prevents valid swap operations.

**Vulnerable Code Example** (LoopFi):
```solidity
function _deposit(...) internal returns (uint256) {
if (collateralParams.auxSwap.assetIn != address(0)) {
        if (
            collateralParams.auxSwap.assetIn != collateralParams.targetToken || // Wrong check!
            collateralParams.auxSwap.recipient != address(this)
        ) revert PositionAction__deposit_InvalidAuxSwap();
    }
}
```

**Impact**: Cannot swap tokens before depositing, feature completely unusable.

**Mitigation**: Remove the incorrect equality check.

### 201. ERC4626 Position Action Withdraw Address Mismatch (LoopFi)
**Pattern**: Withdrawing from wrong address in position actions.

**Vulnerable Code Example** (LoopFi):
```solidity
function _onWithdraw(address vault, address /*position*/, address dst, uint256 amount)
    internal override returns (uint256) {
    uint256 collateralWithdrawn = ICDPVault(vault).withdraw(address(this), amount);
    // Should use position parameter!
}
```

**Impact**: Cannot withdraw from positions other than the contract itself.

**Mitigation**: Use the position parameter for withdrawals.

### 202. Native ETH Support Missing in Swaps (LoopFi)
**Pattern**: Swap functions don't pass msg.value to external protocols.

**Vulnerable Code Example** (LoopFi):
```solidity
function swap(...) external payable { // Function is payable
    if (swapParams.swapProtocol == SwapProtocol.BALANCER) {
        balancerVault.batchSwap( // Missing: {value: msg.value}
            // ...
        );
    }
}
```

**Impact**: Cannot use native ETH as input for swaps.

**Mitigation**: Pass msg.value in external calls.

### 203. Emission Schedule Update Timing Issues (LoopFi)
**Pattern**: Reward distribution uses old rate during schedule transitions.

**Vulnerable Code Example** (LoopFi):
```solidity
function setScheduledRewardsPerSecond() internal {
    if (i > emissionScheduleIndex) {
        emissionScheduleIndex = i;
        _massUpdatePools(); // Uses old rewardsPerSecond!
        rewardsPerSecond = uint256(emissionSchedule[i - 1].rewardsPerSecond);
    }
}
```

**Impact**: Incorrect reward distribution during schedule changes.

**Mitigation**: Calculate rewards with both old and new rates for transition period.

### 204. ERC4626 Slippage Vulnerability During Vault Operations (LoopFi)
**Pattern**: No slippage protection when interacting with ERC4626 vaults in position actions.

**Vulnerable Code Example** (LoopFi):
```solidity
function _onDeposit(address vault, address /*position*/, address src, uint256 amount)
    internal override returns (uint256) {
    if (src != collateral) {
        IERC20(underlying).forceApprove(collateral, amount);
        amount = IERC4626(collateral).deposit(amount, address(this)); // No slippage check!
    }
    return ICDPVault(vault).deposit(address(this), amount);
}
```

**Impact**: Users vulnerable to sandwich attacks and exchange rate manipulation.

**Mitigation**: Add minimum shares parameter and validation.

### 205. Discount Fee Exploitation via Self-Trading (Ditto)
**Pattern**: Attacker can trigger discount fees and claim them through vault ownership, profiting from the mechanism.

**Vulnerable Code Example** (Ditto):
```solidity
function _matchIsDiscounted(MTypes.HandleDiscount memory h) external onlyDiamond {
    // ...
    if (pctOfDiscountedDebt > C.DISCOUNT_THRESHOLD && !LibTStore.isForcedBid()) {
        // Calculate fee based on total debt
        uint256 discountPenaltyFee = uint64(LibAsset.discountPenaltyFee(Asset));
        uint256 ercDebtMinusTapp = h.ercDebt - Asset.ercDebtFee;
        
        // Mint fee as new debt
        uint104 newDebt = uint104(ercDebtMinusTapp.mul(discountPenaltyFee));
        Asset.ercDebt += newDebt;
        
        // Mint to yDUSD vault
        IERC20(h.asset).mint(s.yieldVault[h.asset], newDebt);
    }
}
```

**Attack Scenario**:
1. Attacker owns significant share of yDUSD vault
2. Creates trades at discount prices to trigger fees
3. Fees minted to vault increase share value
4. Profit exceeds trading losses after 2+ days

**Impact**: Attacker can mint free DUSD by exploiting the fee mechanism.

**Mitigation**: Base fees on actual traded amount rather than total debt.

### 206. Minting DUSD with Less Collateral via Cancel Short (Ditto)
**Pattern**: Using stale price and low CR when canceling partial short positions to mint DUSD with insufficient collateral.

**Vulnerable Code Example** (Ditto):
```solidity
function cancelShort(address asset, uint16 id) internal {
    // ...
    if (shortRecord.status == SR.PartialFill) {
        uint256 minShortErc = LibAsset.minShortErc(Asset);
        if (shortRecord.ercDebt < minShortErc) {
            uint88 debtDiff = uint88(minShortErc - shortRecord.ercDebt);
            
            // Uses stale price and potentially low CR
            uint88 collateralDiff = shortOrder.price.mulU88(debtDiff).mulU88(cr);
            
            // Mints DUSD with less collateral than required
            s.assetUser[asset][shorter].ercEscrowed += debtDiff;
        }
    }
}
```

**Impact**: Users can mint DUSD at below 100% CR, creating unbacked stablecoins.

**Mitigation**: Use current oracle price and enforce minimum CR.

### 207. yDUSD Vault Direct Minting Accounting Bug (Ditto)
**Pattern**: Direct minting to yDUSD vault increases balance without updating totalSupply, breaking share calculations.

**Vulnerable Code Example** (Ditto):
```solidity
// When discount occurs:
IERC20(h.asset).mint(s.yieldVault[h.asset], newDebt); // Increases balance

// Later when users deposit:
function previewDeposit(uint256 assets) public view returns (uint256) {
    return _convertToShares(assets, Math.Rounding.Down);
}

function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
    // shares = assets * (0 + 1) / newDebt = 0 (rounds down)
    return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
}
```

**Impact**: Depositors receive 0 shares and lose all deposited assets.

**Mitigation**: Implement proper auto-compounding mechanism like xERC4626.

### 208. yDUSD Withdrawal Timelock Bypass (Ditto)
**Pattern**: Users can use another account's withdrawal proposal to bypass the 7-day timelock.

**Vulnerable Code Example** (Ditto):
```solidity
function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
    // Uses msg.sender's proposal
    WithdrawStruct storage withdrawal = withdrawals[msg.sender];
    
    // But withdraws from owner's account
    _withdraw(_msgSender(), receiver, owner, amountProposed, shares);
}
```

**Attack**:
1. Attacker approves shares to accomplice
2. Accomplice has existing withdrawal proposal
3. Attacker withdraws using accomplice's timelock status

**Impact**: Complete bypass of 7-day withdrawal timelock.

**Mitigation**: Require `msg.sender == owner` for withdrawals.

### 209. Free DUSD Minting and Liquidation Reward Exploit (Ditto)
**Pattern**: Combining decreaseCollateral and cancelShort with CR < 1 to create liquidatable positions for profit.

**Vulnerable Code Example** (Ditto):
```solidity
// Create short with CR < 1
function createLimitShort(asset, price, minShortErc, orderHintArray, shortHintArray, 70); // 70% CR

// After partial fill:
decreaseCollateral(shortRecordId, amount); // Remove collateral added for minShortErc
cancelShort(orderId); // Mints DUSD with only 70% collateral

// Position now liquidatable
```

**Impact**: Attacker mints free DUSD and earns liquidation rewards.

**Mitigation**: Check resulting CR after operations is above liquidation threshold.

### 210. Arbitrary Call Vulnerability in Funding Withdrawal (JOJO)
**Pattern**: User-controlled external calls during withdrawal allowing arbitrary contract interactions.

**Vulnerable Code Example** (JOJO):
```solidity
function _withdraw(..., address to, ..., bytes memory param) private {
    // ... withdrawal logic ...
    
    if (param.length != 0) {
        require(Address.isContract(to), "target is not a contract");
        (bool success,) = to.call(param); // VULNERABLE: Arbitrary call
        if (success == false) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }
}
```

**Attack Vector**: Attacker can execute withdrawal of 1 wei to USDC contract and pass calldata to transfer arbitrary USDC amount to themselves.

**Impact**: Complete drainage of all funds from JOJODealer.

**Mitigation**: Whitelist allowed contracts or remove arbitrary call functionality.

### 211. FundingRateArbitrage Rounding Exploitation (JOJO)
**Pattern**: Incorrect rounding direction in withdrawal calculations allows draining the contract.

**Vulnerable Code Example** (JOJO):
```solidity
function requestWithdraw(uint256 repayJUSDAmount) external {
    jusdOutside[msg.sender] -= repayJUSDAmount;
    uint256 index = getIndex();
    uint256 lockedEarnUSDCAmount = jusdOutside[msg.sender].decimalDiv(index); // Rounds down!
    require(
        earnUSDCBalance[msg.sender] >= lockedEarnUSDCAmount,
        "lockedEarnUSDCAmount is bigger than earnUSDCBalance"
    );
    withdrawEarnUSDCAmount = earnUSDCBalance[msg.sender] - lockedEarnUSDCAmount;
}
```

**Attack Scenario**:
1. Attacker deposits and inflates share price
2. Makes small deposits to get shares
3. Withdraws with minimal JUSD repayment
4. Due to rounding down, gets more USDC than entitled
5. Repeats until contract drained

**Impact**: Complete drainage of JUSD from the contract.

**Mitigation**: Round up instead of down for `lockedEarnUSDCAmount`.

### 212. Interest Rate Calculation Mismatch (JOJO)
**Pattern**: `getTRate()` and `accrueRate()` use different formulas causing calculation discrepancies.

**Vulnerable Code Example** (JOJO):
```solidity
function accrueRate() public {
    uint256 currentTimestamp = block.timestamp;
    if (currentTimestamp == lastUpdateTimestamp) {
        return;
    }
    uint256 timeDifference = block.timestamp - uint256(lastUpdateTimestamp);
    tRate = tRate.decimalMul((timeDifference * borrowFeeRate) / Types.SECONDS_PER_YEAR + 1e18);
    lastUpdateTimestamp = currentTimestamp;
}

function getTRate() public view returns (uint256) {
    uint256 timeDifference = block.timestamp - uint256(lastUpdateTimestamp);
    return tRate + (borrowFeeRate * timeDifference) / Types.SECONDS_PER_YEAR; // Different formula!
}
```

**Impact**: Incorrect calculations in all dependent functions including liquidations, flash loans, and collateral checks.

**Mitigation**: Use consistent calculation formula in both functions.

### 213. Withdrawal Request Using Wrong Address (JOJO)
**Pattern**: Using `msg.sender` instead of `from` parameter in withdrawal requests.

**Vulnerable Code Example** (JOJO):
```solidity
function requestWithdraw(
    Types.State storage state,
    address from,
    uint256 primaryAmount,
    uint256 secondaryAmount
) external {
    require(isWithdrawValid(state, msg.sender, from, primaryAmount, secondaryAmount), Errors.WITHDRAW_INVALID);
    state.pendingPrimaryWithdraw[msg.sender] = primaryAmount; // Should be 'from'!
    state.pendingSecondaryWithdraw[msg.sender] = secondaryAmount;
    state.withdrawExecutionTimestamp[msg.sender] = block.timestamp + state.withdrawTimeLock;
    emit RequestWithdraw(msg.sender, primaryAmount, secondaryAmount, state.withdrawExecutionTimestamp[msg.sender]);
}
```

**Impact**: Cannot initiate withdrawals on behalf of other users even with proper allowance, potentially stranding funds.

**Mitigation**: Replace all `msg.sender` occurrences with `from` parameter.

### 214. FundingRateArbitrage Share Inflation Attack (JOJO)
**Pattern**: Classic ERC4626-style inflation attack through donation allowing theft of subsequent deposits.

**Vulnerable Code Example** (JOJO):
```solidity
function getIndex() public view returns (uint256) {
    if (totalEarnUSDCBalance == 0) {
        return 1e18;
    } else {
        return SignedDecimalMath.decimalDiv(getNetValue(), totalEarnUSDCBalance);
    }
}

function deposit(uint256 amount) external {
    // ...
    uint256 earnUSDCAmount = amount.decimalDiv(getIndex());
    // If index is inflated, earnUSDCAmount rounds to 0
}
```

**Attack**:
1. Deposit 1 share
2. Donate 100,000e6 USDC
3. Index becomes 100,000e18
4. Subsequent deposits under 100,000e6 receive 0 shares

**Impact**: Complete theft of subsequent user deposits.

**Mitigation**: Implement virtual offset as recommended by OpenZeppelin.

### 215. Bearer Asset Transfer Exploit (Astaria)
**Pattern**: Lien tokens act as bearer assets, allowing malicious lenders to block loan repayments by transferring to blocklisted addresses.

**Vulnerable Code Example** (Astaria):
```solidity
function _getPayee(LienStorage storage s, uint256 lienId) internal view returns (address) {
    return s.lienMeta[lienId].payee != address(0) ? s.lienMeta[lienId].payee : ownerOf(lienId);
}

// Payments sent to lien token owner
function _payment(LienStorage storage s, Stack[] memory stack, ...) {
    s.TRANSFER_PROXY.tokenTransferFrom(stack.lien.token, payer, payee, amount);
}
```

**Attack Scenario**:
1. Lender offers loan in USDT/USDC
2. Transfers lien token to USDC blocklist address
3. Borrower cannot repay, loan goes to liquidation
4. All auction bids fail due to blocklist
5. Liquidator claims collateral for free

**Impact**: Borrower loses collateral, other lenders lose funds.

**Mitigation**: Pull-based payment system or token allowlist.

### 216. Clearing House Arbitrary Settlement (Astaria)
**Pattern**: ClearingHouse.safeTransferFrom can be called by anyone with arbitrary parameters, allowing collateral theft.

**Vulnerable Code Example** (Astaria):
```solidity
function safeTransferFrom(address from, address to, uint256 identifier, uint256 amount, bytes calldata data) {
    // No validation that auction has occurred
    address paymentToken = bytes32(identifier).fromLast20Bytes();
    _execute(from, to, paymentToken, amount);
    // Deletes all liens and burns collateral token!
}
```

**Impact**: Anyone can wipe collateral state with zero payment.

**Mitigation**: Change AND to OR in settleAuction validation:
```solidity
if (s.collateralIdToAuction[collateralId] == bytes32(0) ||
    ERC721(s.idToUnderlying[collateralId].tokenContract).ownerOf(...) != s.clearingHouse[collateralId]) {
    revert InvalidCollateralState(InvalidCollateralStates.NO_AUCTION);
}
```

### 217. Vault Strategy Bypass (Astaria)
**Pattern**: Borrowers can bypass vault's validation and take loans without proper authorization.

**Vulnerable Code Example** (Astaria):
```solidity
function _validateCommitment(IAstariaRouter.Commitment calldata params, address receiver) internal view {
    if (msg.sender != holder && receiver != holder && receiver != operator && !CT.isApprovedForAll(holder, msg.sender)) {
        revert InvalidRequest(InvalidRequestReason.NO_AUTHORITY);
    }
    // Passes if receiver == holder, even if msg.sender unauthorized!
}
```

**Attack**: Attacker sets receiver to collateral owner address, bypassing authorization.

**Impact**: Unauthorized loans against any collateral.

**Mitigation**: Separate authorization checks for msg.sender and receiver.

### 218. Missing Strategy Deadline Validation (Astaria)
**Pattern**: VaultImplementation doesn't check strategy deadline, allowing expired strategies.

**Vulnerable Code Example** (Astaria):
```solidity
function _validateCommitment(IAstariaRouter.Commitment calldata params, address receiver) internal view {
    // Missing: if (block.timestamp > params.lienRequest.strategy.deadline) revert Expired();
    // Only validates signature, not deadline
}
```

**Impact**: Borrowers can use outdated strategies with potentially unfavorable terms.

**Mitigation**: Add deadline validation in vault commitment validation.

### 219. Liquidation InitialAsk Overflow (Astaria)
**Pattern**: liquidationInitialAsk > 2^88-1 causes liquidation to revert, permanently locking collateral.

**Vulnerable Code Example** (Astaria):
```solidity
auctionData.startAmount = stack[0].lien.details.liquidationInitialAsk.safeCastTo88();
// Reverts if liquidationInitialAsk > type(uint88).max
```

**Impact**: Collateral permanently locked, cannot be liquidated.

**Mitigation**: Use uint256 for auction startAmount.

### 220. Strategist Fee Overflow Attack (Astaria)
**Pattern**: Extremely high vault fees cause repayment to revert.

**Vulnerable Code Example** (Astaria):
```solidity
uint88 feeInShares = convertToShares(fee).safeCastTo88();
// Reverts if fee converts to shares > uint88 max
```

**Attack**: Strategist sets fee to 1e13, causing overflow.

**Impact**: Borrowers cannot repay, forced liquidation.

**Mitigation**: Validate vault fee within reasonable range on creation.

### 221. Liquidation DOS via liquidationInitialAsk (Astaria)
**Pattern**: Borrowers can block future borrowing by setting low liquidationInitialAsk.

**Vulnerable Code Example** (Astaria):
```solidity
for (uint256 i = stack.length; i > 0; ) {
    potentialDebt += _getOwed(newStack[j], newStack[j].point.end);
    if (potentialDebt > newStack[j].lien.details.liquidationInitialAsk) {
        revert InvalidState(InvalidStates.INITIAL_ASK_EXCEEDED);
    }
}
```

**Attack**: Set liquidationInitialAsk equal to loan amount, blocking all future loans.

**Impact**: Borrower DOS from taking additional loans.

**Mitigation**: Only check total stack debt against position 0 liquidationInitialAsk.

### 222. Public Vault Slope Corruption (Astaria)
**Pattern**: Buyout doesn't increase destination vault's slope.

**Vulnerable Code Example** (Astaria):
```solidity
function buyoutLien(Stack[] calldata stack, uint8 position, ...) {
    // Burns old lien, decreases old vault slope
    if (_isPublicVault(s, payee)) {
        IPublicVault(payee).handleBuyoutLien(...);
    }
    // Creates new lien but doesn't increase new vault slope!
}
```

**Impact**: LPs lose interest income, borrowers don't pay interest.

**Mitigation**: Increase slope when creating new lien in buyout.

### 223. Collateral Recovery After Liquidation (Astaria)
**Pattern**: Liquidated collateral can be used to take new loans.

**Vulnerable Code Example** (Astaria):
```solidity
function liquidatorNFTClaim(OrderParameters memory params) {
    // Transfers NFT but doesn't settle auction
    ERC721(token).safeTransferFrom(address(this), liquidator, tokenId);
    // CollateralToken still exists, can be used for new loans!
}
```

**Impact**: Vault drained by taking loans without real collateral.

**Mitigation**: Settle auction in liquidatorNFTClaim.

### 224. Lien Transfer to Public Vault Bypass (Astaria)
**Pattern**: Attacker can transfer liens to uncreated public vault addresses.

**Vulnerable Code Example** (Astaria):
```solidity
function transferFrom(address from, address to, uint256 id) {
    if (_isPublicVault(s, to)) {
        revert InvalidState(InvalidStates.PUBLIC_VAULT_RECIPIENT);
    }
    // But vault might not exist yet!
}
```

**Attack**: Transfer lien to predicted public vault address before creation.

**Impact**: Borrower cannot repay, forced liquidation.

**Mitigation**: Add `require(to.code.length > 0)` for vault transfers.

### 225. Withdraw Reserve Calculation Error (Astaria)
**Pattern**: processEpoch incorrectly sets withdrawReserve to 0 when totalAssets <= expected.

**Vulnerable Code Example** (Astaria):
```solidity
if (totalAssets() > expected) {
    s.withdrawReserve = (totalAssets() - expected).mulWadDown(s.liquidationWithdrawRatio).safeCastTo88();
} else {
    s.withdrawReserve = 0; // Wrong! Should still send proportional amount
}
```

**Impact**: WithdrawProxy receives no funds despite having claims.

**Mitigation**: Always calculate proportional withdraw reserve.

### 226. YIntercept Underflow in processEpoch (Astaria)
**Pattern**: Large withdrawals cause yIntercept calculation to underflow.

**Vulnerable Code Example** (Astaria):
```solidity
_setYIntercept(s, s.yIntercept - totalAssets().mulDivDown(s.liquidationWithdrawRatio, 1e18));
// Underflows if most users withdraw
```

**Impact**: Epoch processing fails, users cannot withdraw.

**Mitigation**: Call accrue() before processEpoch to update yIntercept.

### 227. Decimal Mismatch in Liquidation Pricing (Astaria)
**Pattern**: Non-18 decimal assets cause incorrect auction starting prices.

**Vulnerable Code Example** (Astaria):
```solidity
startingPrice: stack[0].lien.details.liquidationInitialAsk, // Assumes 18 decimals
settlementToken: stack[position].lien.token, // May be 6 decimals (USDC)
```

**Impact**: Auction starts at 1e12x intended price for USDC.

**Mitigation**: Scale liquidationInitialAsk by token decimals.

### 228. Refinancing Attack on Liquidation (Astaria)
**Pattern**: Malicious refinancing just before liquidation with low initialAsk.

**Attack Scenario**:
1. User takes 3 ETH loan with 100 ETH liquidationInitialAsk
2. Before liquidation, attacker refinances with 0.1 ETH initialAsk
3. NFT liquidated for far below fair value

**Impact**: Borrower loses NFT value due to manipulated auction price.

**Mitigation**: Prevent refinancing close to liquidation or maintain minimum initialAsk.

### 229. Commitment Replay Attack (Astaria)
**Pattern**: Same commitment signature can be used multiple times to obtain additional loans.

**Vulnerable Code Example** (Astaria):
```solidity
function _validateCommitment(IAstariaRouter.Commitment calldata params, address receiver) internal view {
    // Only validates signature, doesn't track if commitment was already used
    address recovered = ecrecover(
        keccak256(_encodeStrategyData(s, params.lienRequest.strategy, params.lienRequest.merkle.root)),
        params.lienRequest.v,
        params.lienRequest.r,
        params.lienRequest.s
    );
}
```

**Attack Procedure**:
1. User takes loan via Router with valid commitment
2. User manually transfers NFT to CollateralToken
3. Calls commitToLien directly on vault with same commitment
4. Changes strategy.vault to generate new lienId
5. Adds previous transaction to stack to pass validation

**Impact**: Multiple loans using single approved commitment.

**Mitigation**: Add nonce system to track used commitments.

### 230. Buyout Lien Liquidation Ask Validation Error (Astaria)
**Pattern**: Buyout validation uses old stack instead of new stack after replacement.

**Vulnerable Code Example** (Astaria):
```solidity
function _buyoutLien(LienStorage storage s, ILienToken.LienActionBuyout calldata params) internal {
    // ... buyout logic ...
    for (uint256 i = params.encumber.stack.length; i > 0; ) {
        potentialDebt += _getOwed(params.encumber.stack[j], params.encumber.stack[j].point.end);
        if (potentialDebt > params.encumber.stack[j].lien.details.liquidationInitialAsk) { // Uses old stack!
            revert InvalidState(InvalidStates.INITIAL_ASK_EXCEEDED);
        }
    }
    // ... replace with new lien ...
    newStack = _replaceStackAtPositionWithNewLien(s, params.encumber.stack, params.position, newLien, ...);
}
```

**Impact**: Buyout may succeed with insufficient liquidationInitialAsk for covering total debt.

**Mitigation**: Validate against newStack after replacement.

### 231. Settlement Check Logic Error (Astaria)
**Pattern**: AND condition should be OR in settleAuction validation.

**Vulnerable Code Example** (Astaria):
```solidity
function settleAuction(uint256 collateralId) public {
    if (
        s.collateralIdToAuction[collateralId] == bytes32(0) &&
        ERC721(s.idToUnderlying[collateralId].tokenContract).ownerOf(
            s.idToUnderlying[collateralId].tokenId
        ) != s.clearingHouse[collateralId]
    ) {
        revert InvalidCollateralState(InvalidCollateralStates.NO_AUCTION);
    }
}
```

**Impact**: ClearingHouse.safeTransferFrom can execute even without auction.

**Mitigation**: Change AND to OR condition.

### 232. Router Approval Requirement Mismatch (Astaria)
**Pattern**: commitToLiens requires approval for all instead of individual NFT approval.

**Vulnerable Code Example** (Astaria):
```solidity
function _validateCommitment(IAstariaRouter.Commitment calldata params, address receiver) internal view {
    if (
        msg.sender != holder &&
        receiver != holder &&
        receiver != operator && // Should check msg.sender == operator
        !CT.isApprovedForAll(holder, msg.sender)
    ) {
        revert InvalidRequest(InvalidRequestReason.NO_AUTHORITY);
    }
}
```

**Impact**: Standard NFT approval workflow doesn't work, forcing users to approve entire collection.

**Mitigation**: Change to `msg.sender != operator`.

### 233. Self-Liquidation Incentive Exploit (Astaria)
**Pattern**: Borrowers can liquidate themselves to capture liquidation fees.

**Vulnerable Code Example** (Astaria):
```solidity
function canLiquidate(ILienToken.Stack memory stack) public view returns (bool) {
    return (stack.point.end <= block.timestamp ||
        msg.sender == s.COLLATERAL_TOKEN.ownerOf(stack.lien.collateralId));
}
```

**Attack Scenario**:
1. Borrower takes 10 WETH loan
2. Before loan expires, borrower calls liquidate()
3. Borrower set as liquidator, gets 13% liquidation fee
4. Keeps original 10 WETH plus 1.3 WETH bonus

**Impact**: Lenders suffer losses while borrowers profit from defaults.

**Mitigation**: Prevent self-liquidation until loans are publicly liquidatable.

### 234. Private Vault ERC777 Griefing (Astaria)
**Pattern**: Private vault owners can refuse loan repayments via ERC777 callbacks.

**Vulnerable Code Example** (Astaria):
```solidity
function _payment(LienStorage storage s, Stack[] memory stack, ...) internal {
    // For private vaults, payment goes to owner
    address payee = _getPayee(s, lienId);
    s.TRANSFER_PROXY.tokenTransferFrom(stack.lien.token, payer, payee, amount);
}

function recipient() public view returns (address) {
    if (IMPL_TYPE() == uint8(IAstariaRouter.ImplementationType.PublicVault)) {
        return address(this);
    } else {
        return owner(); // Private vault sends to owner
    }
}
```

**Attack**: Private vault owner reverts in ERC777 tokensReceived callback.

**Impact**: Borrower forced into liquidation despite attempting repayment.

**Mitigation**: Pull-based payment system for private vaults.

### 235. Zero Transfer Revert DoS (Astaria)
**Pattern**: Some tokens revert on zero-value transfers causing DoS.

**Vulnerable Code Example** (Astaria):
```solidity
function transferWithdrawReserve() public {
    uint256 withdrawBalance = ERC20(asset()).balanceOf(address(this));
    // If balance is 0 and token reverts on zero transfer
    ERC20(asset()).safeTransfer(currentWithdrawProxy, withdrawBalance);
}
```

**Attack**:
1. User A calls commitToLien, pending in mempool
2. User B front-runs with transferWithdrawReserve()
3. If vault has no balance and token reverts on zero transfer
4. User A's transaction reverts in _beforeCommitToLien

**Impact**: DoS of commitToLien and updateVaultAfterLiquidation.

**Mitigation**: Check balance > 0 before transfer.

### 236. Missing Pause Check on Private Vault Deposit (Astaria)
**Pattern**: Private vault deposits bypass pause checks.

**Vulnerable Code Example** (Astaria):
```solidity
// PublicVault has whenNotPaused
function deposit(uint256 amount, address receiver)
    public
    override(ERC4626Cloned)
    whenNotPaused
    returns (uint256) { ... }

// But Vault (private) doesn't
function deposit(uint256 amount, address receiver)
    public
    virtual
    returns (uint256) { // No whenNotPaused!
    VIData storage s = _loadVISlot();
    require(s.allowList[msg.sender] && receiver == owner());
    ERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);
    return amount;
}
```

**Impact**: Private vaults can receive deposits even when protocol is paused/shutdown.

**Mitigation**: Add whenNotPaused modifier to private vault deposit.

### 237. Strategist Interest Reward Miscalculation (Astaria)
**Pattern**: Strategist rewards calculated on full loan amount instead of payment amount.

**Vulnerable Code Example** (Astaria):
```solidity
function _payment(LienStorage storage s, Stack[] memory activeStack, ...) internal {
    if (isPublicVault) {
        IPublicVault(lienOwner).beforePayment(
            IPublicVault.BeforePaymentParams({
                interestOwed: owed - stack.point.amount,
                amount: stack.point.amount, // Should be payment amount!
                lienSlope: calculateSlope(stack)
            })
        );
    }
}
```

**Impact**: Strategists earn excessive rewards even on minimal payments.

**Mitigation**: Pass actual payment amount instead of stack.point.amount.

### 238. Fee-on-Transfer Token Lock (Astaria)
**Pattern**: PublicVault accounting breaks with fee-on-transfer tokens.

**Vulnerable Code Example** (Astaria):
```solidity
function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
    ERC20(asset()).safeTransferFrom(msg.sender, address(this), assets);
    _mint(receiver, shares);
    // If token takes fee, actual received < assets
    // But shares minted based on assets
}
```

**Impact**: Later withdrawers cannot redeem as vault has less assets than expected.

**Mitigation**: Calculate actual received amount or whitelist tokens.

### 239. Interest Compounding on Partial Payments (Astaria)
**Pattern**: Each partial payment adds interest to principal, compounding debt.

**Vulnerable Code Example** (Astaria):
```solidity
function _payment(LienStorage storage s, Stack[] memory activeStack, ...) internal {
    uint256 owed = _getOwed(stack, block.timestamp); // principal + interest
    stack.point.amount = owed.safeCastTo88(); // Updates principal to include interest
    stack.point.last = block.timestamp.safeCastTo40();
    
    if (stack.point.amount > amount) {
        stack.point.amount -= amount.safeCastTo88(); // Remaining includes compounded interest
    }
}
```

**Impact**: Despite claiming simple interest, protocol charges compound interest.

**Mitigation**: Track accrued interest separately from principal.

### 240. Liquidation During Auction Window (Astaria)
**Pattern**: Adversary can settle auction with minimal payment using dutch auction.

**Vulnerable Code Example** (Astaria):
```solidity
function _generateValidOrderParameters(...) internal returns (OrderParameters memory) {
    considerationItems[0] = ConsiderationItem(
        ItemType.ERC20,
        settlementToken,
        uint256(0),
        prices[0], // Starting price
        prices[1], // Ending price: 1000 wei
        payable(address(s.clearingHouse[collateralId]))
    );
}
```

**Attack**:
1. Dutch auction price drops to 1000 wei
2. Attacker transfers 1001 wei to ClearingHouse
3. Calls safeTransferFrom to settle auction
4. NFT claimed by liquidator, lenders lose

**Mitigation**: Validate auction completion and NFT transfer.

### 241. Public Vault yIntercept Overflow (Astaria)
**Pattern**: Unchecked addition can overflow yIntercept.

**Vulnerable Code Example** (Astaria):
```solidity
function _increaseYIntercept(VaultData storage s, uint256 amount) internal {
    s.yIntercept += amount.safeCastTo88(); // Only 88 bits
}
```

**Impact**: totalAssets calculation breaks, preventing withdrawals.

**Mitigation**: Use checked arithmetic or larger storage type.

### 242. Public Vault Slope Overflow (Astaria)
**Pattern**: High interest rates cause slope overflow.

**Vulnerable Code Example** (Astaria):
```solidity
function afterPayment(uint256 computedSlope) public onlyLienToken {
    s.slope += computedSlope.safeCastTo48(); // Can overflow with multiple loans
}
```

**Impact**: Incorrect totalAssets calculation, broken vault accounting.

**Mitigation**: Remove unchecked blocks, consider larger storage.

### 243. Minimum Deposit Calculation Error (Astaria)
**Pattern**: Non-18 decimal tokens have excessive minimum deposits.

**Vulnerable Code Example** (Astaria):
```solidity
function minDepositAmount() public view returns (uint256) {
    if (ERC20(asset()).decimals() == uint8(18)) {
        return 100 gwei;
    } else {
        return 10**(ERC20(asset()).decimals() - 1); // 0.1 tokens regardless of value
    }
}
```

**Impact**: WBTC minimum deposit > $2000, excluding many users.

**Mitigation**: Scale minimum based on decimal count:
```solidity
if (decimals < 4) return 10**(decimals - 1);
else if (decimals < 8) return 10**(decimals - 2);
else return 10**(decimals - 6);
```

### 244. ProcessEpoch Overflow in Withdraw Reserve (Astaria)
**Pattern**: Unchecked multiplication can overflow with arbitrary tokens.

**Vulnerable Code Example** (Astaria):
```solidity
unchecked {
    if (totalAssets() > expected) {
        s.withdrawReserve = (totalAssets() - expected)
            .mulWadDown(s.liquidationWithdrawRatio)
            .safeCastTo88();
    }
}
```

**Impact**: ProcessEpoch fails, blocking withdrawals.

**Mitigation**: Remove unchecked block or validate totalAssets magnitude.

### 245. WithdrawProxy Early Redemption (Astaria)
**Pattern**: Users can redeem before vault transfers withdraw reserves.

**Vulnerable Code Example** (Astaria):
```solidity
modifier onlyWhenNoActiveAuction() {
    if (s.finalAuctionEnd != 0) { // 0 before auction starts
        revert InvalidState(InvalidStates.NOT_CLAIMED);
    }
    _;
}

function redeem(uint256 shares, address receiver, address owner) public onlyWhenNoActiveAuction {
    if (totalAssets() > 0) { // Can be satisfied by small donation
        // Allows redemption
    }
}
```

**Attack**: Deposit small amount to WithdrawProxy, enabling early unfair redemption.

**Impact**: Early redeemers get less than fair share.

**Mitigation**: Add explicit flag for when withdrawals are safe.

### 246. Lien Position Deletion Failure (Astaria)
**Pattern**: Using memory instead of storage prevents lien deletion.

**Vulnerable Code Example** (Astaria):
```solidity
function _paymentAH(
    LienStorage storage s,
    address token,
    AuctionStack[] memory stack, // Should be storage!
    uint256 position,
    uint256 payment,
    address payer
) internal returns (uint256) {
    delete s.lienMeta[lienId]; // Works
    delete stack[position]; // No effect on storage!
}
```

**Impact**: Ghost liens remain in storage after repayment.

**Mitigation**: Change parameter to storage or handle deletion separately.

### 247. Strategist Buyout Griefing (Astaria)
**Pattern**: Strategist can prevent withdrawals by repeatedly buying out liens.

**Attack Scenario**:
1. LPs signal withdrawal for epoch
2. Strategist front-runs transferWithdrawReserve
3. Calls buyoutLien to consume available funds
4. WithdrawProxy remains unfunded
5. Repeat indefinitely

**Impact**: LPs permanently locked from withdrawing.

**Mitigation**: Enforce transferWithdrawReserve before buyout like commitToLien.

### 248. Non-18 Decimal Token Support Issues (Astaria)
**Pattern**: Multiple calculation errors with non-18 decimal tokens.

**Issues**:
- PublicVault decimals hardcoded to 18
- liquidationWithdrawRatio calculations assume 18 decimals
- WithdrawProxy calculations use 1e18 constants
- minDepositAmount excessive for low decimal tokens

**Impact**: Vault unusable or broken with USDC, WBTC, etc.

**Mitigation**: Make decimals match underlying token throughout.

### 249. ProcessEpoch YIntercept Underflow (Astaria)
**Pattern**: High liquidationWithdrawRatio causes underflow.

**Vulnerable Code Example** (Astaria):
```solidity
_setYIntercept(
    s,
    s.yIntercept - totalAssets().mulDivDown(s.liquidationWithdrawRatio, 1e18)
);
```

**Impact**: ProcessEpoch reverts, blocking epoch transitions.

**Mitigation**: Call accrue() before processEpoch to update yIntercept.

### 250. Liquidation Accounting Gap (Astaria)
**Pattern**: Missing updateVaultAfterLiquidation prevents proper WithdrawProxy setup.

**Vulnerable Code Example** (Astaria):
```solidity
// Liquidation can happen without notifying vault
// If withdrawProxy not deployed, it never gets auction funds
```

**Impact**: LPs don't receive liquidation proceeds if epoch boundary is near.

**Mitigation**: Ensure updateVaultAfterLiquidation is always called.

### 251. GMX Cooldown Redemption Blocking (RedactedCartel)
**Pattern**: GMX's cooldownDuration on GlpManager prevents redemptions if any deposit occurred within the cooldown period.

**Vulnerable Code Example**:
```solidity
// GMX GlpManager enforces cooldown
function _removeLiquidity(...) {
    require(lastAddedAt[account] + cooldownDuration <= block.timestamp);
}
```

**Attack Scenarios**:
1. Natural blocking: With 10% of GMX users using Pirex, redemptions fail 95% of the time
2. Griefing attack: Deposit 1 wei every 15 minutes to permanently block redemptions (cost: ~$3.5k/year)
3. GMX parameter changes: Increasing cooldownDuration to 2 days breaks redemptions

**Impact**: Users cannot withdraw funds from PirexGmx.

**Mitigation**: Reserve specific time ranges for redemption-only periods.

### 252. Dynamic Emission Rate Reward Miscalculation (RedactedCartel)
**Pattern**: Reward distribution assumes constant emission rates but GMX uses dynamic rates.

**Vulnerable Code Example**:
```solidity
// Calculates rewards linearly
uint256 rewards = globalState.rewards +
    (block.timestamp - lastUpdate) *
    lastSupply;
```

**Real Scenario**:
- Alice stakes when emission rate is 2 esGMX/sec
- Bob stakes when rate drops to 1 esGMX/sec
- Alice receives less rewards than entitled due to linear calculation

**Impact**: Some users lose rewards while others receive extra.

**Mitigation**: Implement RewardPerToken pattern to handle dynamic rates.

### 253. Zero Share Withdrawal Attack (RedactedCartel)
**Pattern**: Rounding down in share calculation allows free asset withdrawal.

**Vulnerable Code Example**:
```solidity
function withdraw(uint256 assets, address receiver, address owner) public {
    shares = previewWithdraw(assets); // Can round down to 0
    _burn(owner, shares); // Burns 0 shares
    asset.safeTransfer(receiver, assets); // Transfers assets
}
```

**Attack**: With 1000 WETH total assets and 10 shares total supply, withdrawing 99 WETH rounds to 0 shares.

**Mitigation**: Use rounding up in previewWithdraw:
```solidity
uint256 shares = supply == 0 ? assets : assets.mulDivUp(supply, totalAssets());
```

### 254. Small Position Reward Loss (RedactedCartel)
**Pattern**: Users with small positions lose all rewards due to rounding.

**Vulnerable Code Example**:
```solidity
uint256 amount = (rewardState * userRewards) / globalRewards;
// If userRewards << globalRewards, amount rounds to 0
p.userStates[user].rewards = 0; // But rewards cleared anyway
```

**Impact**: Small depositors permanently lose rewards; malicious users can grief by calling claim for victims.

**Mitigation**:
- Implement RewardPerToken approach
- Revert if calculated reward is 0

### 255. GMX Migration Blocking via vGMX/vGLP (RedactedCartel)
**Pattern**: Direct transfers of non-transferable vester tokens block migration.

**Attack**: Send vGMX or vGLP tokens directly to PirexGmx to permanently prevent:
```solidity
function signalTransfer(address _receiver) external {
    require(IERC20(gmxVester).balanceOf(msg.sender) == 0);
    require(IERC20(glpVester).balanceOf(msg.sender) == 0);
}
```

**Impact**: Protocol migration becomes impossible.

**Note**: Vester tokens override transfer methods to revert, limiting attack to GMX insiders.

### 256. Compound Function Manipulation (RedactedCartel)
**Pattern**: Public compound function with user-controlled swap parameters enables MEV.

**Vulnerable Code Example**:
```solidity
function compound(
    uint24 fee, // User controls pool selection
    uint256 amountOutMinimum, // Can be set to 1
    uint160 sqrtPriceLimitX96,
    bool optOutIncentive
) public {
    gmxAmountOut = SWAP_ROUTER.exactInputSingle({
        fee: fee, // Attacker chooses illiquid pool
        amountOutMinimum: amountOutMinimum, // Accepts high slippage
    });
}
```

**Attack**: Route swaps through illiquid pools and sandwich for profit.

**Mitigation**: Use poolFee parameter and on-chain oracle for minimum amounts.

### 257. ERC4626 MaxWithdraw Implementation Error (RedactedCartel)
**Pattern**: MaxWithdraw doesn't account for withdrawal penalties.

**Vulnerable Code**:
```solidity
// In PirexERC4626 (inherited by AutoPxGmx/AutoPxGlp)
function maxWithdraw(address owner) public view returns (uint256) {
    return convertToAssets(balanceOf(owner)); // Ignores penalty
}
```

**Impact**: Calling withdraw with maxWithdraw amount always reverts.

**Mitigation**: Override in AutoPxGmx/AutoPxGlp:
```solidity
function maxWithdraw(address owner) public view override returns (uint256) {
    uint256 assets = convertToAssets(balanceOf(owner));
    uint256 penalty = ... // calculate penalty
    return assets - penalty;
}
```

### 258. Platform Update Approval Loss (RedactedCartel)
**Pattern**: Updating platform address doesn't grant approval to new platform.

**Vulnerable Code**:
```solidity
function setPlatform(address _platform) external onlyOwner {
    platform = _platform; // No approval granted
}
```

**Impact**: Deposits fail after platform update.

**Mitigation**:
```solidity
function setPlatform(address _platform) external onlyOwner {
    gmx.safeApprove(platform, 0);
    gmx.safeApprove(_platform, type(uint256).max);
    platform = _platform;
}
```

### 259. Fee-on-Transfer Token Incompatibility (RedactedCartel)
**Pattern**: depositGlp assumes received amount equals sent amount.

**Vulnerable Code**:
```solidity
t.safeTransferFrom(msg.sender, address(this), tokenAmount);
deposited = gmxRewardRouterV2.mintAndStakeGlp(
    token,
    tokenAmount, // Assumes full amount received
    minUsdg,
    minGlp
);
```

**Impact**: Transactions revert with FOT tokens like USDT.

**Mitigation**:
```solidity
uint256 balanceBefore = t.balanceOf(address(this));
t.safeTransferFrom(msg.sender, address(this), tokenAmount);
uint256 actualAmount = t.balanceOf(address(this)) - balanceBefore;
```

### 260. Direct Reward Claim Bypass (RedactedCartel)
**Pattern**: Anyone can claim rewards directly, bypassing compound logic and fees.

**Attack Flow**:
1. Call `PirexRewards.claim(pxGmx, AutoPxGlp)` directly
2. Rewards sent to vault without compound() execution
3. No fees calculated or harvested
4. pxGmx rewards not tracked in _harvest()

**Impact**:
- Protocol loses fee revenue
- Users lose pxGmx rewards

**Mitigation**: Track previous balances and detect direct transfers.

### 261. Zero TotalSupply Division (RedactedCartel)
**Pattern**: _calculateRewards reverts when RewardTracker totalSupply is 0.

**Vulnerable Code**:
```solidity
uint256 cumulativeRewardPerToken = r.cumulativeRewardPerToken() +
    ((blockReward * precision) / r.totalSupply()); // Division by zero
```

**Impact**: harvest() and claim() become unusable when any RewardTracker is empty.

**Mitigation**: Check totalSupply before division:
```solidity
if (r.totalSupply() == 0) return 0;
```

### 262. Reward Token Mismanagement (RedactedCartel)
**Pattern**: Mismatch between hardcoded rewards in PirexGmx and configurable rewards in PirexRewards.

**Issue**: Owner can:
- Remove hardcoded reward tokens
- Add unsupported tokens
- Clear reward arrays

**Impact**: Users lose rewards when tokens are misconfigured but state is still cleared.

### 263. Hardcoded Swap Router (RedactedCartel)
**Pattern**: SWAP_ROUTER address hardcoded for Arbitrum, incompatible with Avalanche.

**Vulnerable Code**:
```solidity
IV3SwapRouter public constant SWAP_ROUTER =
    IV3SwapRouter(0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45);
```

**Impact**: AutoPxGmx completely broken on Avalanche.

**Mitigation**: Pass router address in constructor.

### 264. GlpManager Slippage During Turbulence (RedactedCartel)
**Pattern**: Compound accepts user-controlled minUsdg/minGlp parameters.

**Risk**: During price volatility or oracle manipulation, compound value can be lost.

**Mitigation**: Use oracle to calculate minimum amounts instead of user input.

### 265. Migration Reward Loss Window (RedactedCartel)
**Pattern**: Between completeMigration and PirexRewards producer update, rewards are lost.

**Vulnerable Flow**:
1. completeMigration() called
2. AutoPxGmx.compound() → old PirexGmx.claimRewards()
3. Returns zero rewards, losing user funds

**Mitigation**: Set pirexRewards = address(0) in migrateReward().

### 266. ConfigureGmxState Approval Accumulation (RedactedCartel)
**Pattern**: Doesn't reset old stakedGmx approval, causing multiple issues.

**Problems**:
1. Can't call function twice if stakedGmx unchanged
2. Old contracts retain spending approval
3. Can't revert to previous stakedGmx addresses

**Mitigation**: Reset old approval before setting new:
```solidity
gmx.safeApprove(address(stakedGmx), 0);
gmx.safeApprove(address(newStakedGmx), type(uint256).max);
```

### 267. ERC4626 Compliance Violations (RedactedCartel)
**Pattern**: maxDeposit/maxMint return type(uint256).max regardless of actual limits.

**Issue**: Violates EIP-4626 requirement to not overestimate capacity.

**Mitigation**:
```solidity
function maxMint(address) public view virtual returns (uint256) {
    if (totalSupply >= maxSupply) return 0;
    return maxSupply - totalSupply;
}
```

### 268. Exchange Rate Manipulation Prevention (PoolTogether H-01)
**Pattern**: Exchange rate calculation incorrectly caps withdrawable assets, preventing rate from ever increasing.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _currentExchangeRate() internal view returns (uint256) {
    uint256 _withdrawableAssets = _yieldVault.maxWithdraw(address(this));
    
    if (_withdrawableAssets >  _totalSupplyToAssets) {
        _withdrawableAssets = _withdrawableAssets - (_withdrawableAssets - _totalSupplyToAssets);
    }
    
    return _withdrawableAssets.mulDiv(_assetUnit, _totalSupplyAmount, Math.Rounding.Down);
}
```

**Impact**: Vault cannot recover from under-collateralization; exchange rate permanently stuck.

**Mitigation**: Remove the artificial cap on withdrawable assets.

### 269. Type Casting Overflow in Withdrawals (PoolTogether H-02)
**Pattern**: Silent downcast from uint256 to uint96 when burning shares.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _burn(address _owner, uint256 _shares) internal virtual override {
    _twabController.burn(msg.sender, _owner, uint96(_shares)); // Silent downcast!
}
```

**Impact**: Users can withdraw full assets while only burning uint96 worth of shares, draining the vault.

**Mitigation**: Use SafeCast library for all type conversions.

### 270. Asset/Share Type Confusion (PoolTogether H-03)
**Pattern**: Function parameters used interchangeably as both assets and shares without conversion.

**Vulnerable Code Example** (PoolTogether):
```solidity
function liquidate(address _account, address _tokenIn, uint256 _amountIn, address _tokenOut, uint256 _amountOut) public {
    if (_amountOut > _liquidatableYield) revert LiquidationAmountOutGTYield(_amountOut, _liquidatableYield);
    
    _increaseYieldFeeBalance(
        (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut
    );
    
    _mint(_account, _amountOut);
}
```

**Impact**: Liquidation logic completely broken due to mixing asset and share amounts.

**Cross References**: Can combine with #363 in meta vaults.

**Mitigation**: Clearly separate asset and share amounts with proper conversion.

### 271. Yield Fee Minting Access Control (PoolTogether H-04)
**Pattern**: Anyone can mint yield fees to any recipient.

**Vulnerable Code Example** (PoolTogether):
```solidity
function mintYieldFee(uint256 _shares, address _recipient) external {
    _requireVaultCollateralized();
    if (_shares > _yieldFeeTotalSupply) revert YieldFeeGTAvailable(_shares, _yieldFeeTotalSupply);
    
    _yieldFeeTotalSupply -= _shares;
    _mint(_recipient, _shares); // Anyone can mint to any address!
    
    emit MintYieldFee(msg.sender, _recipient, _shares);
}
```

**Impact**: Complete theft of protocol yield fees.

**Mitigation**: Remove recipient parameter; only mint to designated yield fee recipient.

### 272. Forced Delegation Removal (PoolTogether H-05)
**Pattern**: sponsor() function can forcefully remove user delegations.

**Vulnerable Code Example** (PoolTogether):
```solidity
function sponsor(uint256 _amount, address _receiver) external {
    _deposit(msg.sender, _receiver, _amount, _amount);
    
    if (_twabController.delegateOf(address(this), _receiver) != SPONSORSHIP_ADDRESS) {
        _twabController.delegate(address(this), _receiver, SPONSORSHIP_ADDRESS);
    }
}
```

**Impact**: Attacker can remove all delegations by sponsoring 0 amount, manipulating lottery odds.

**Mitigation**: Only force delegation if receiver already delegated to sponsorship address.

### 273. Delegation to Zero Address (PoolTogether H-06)
**Pattern**: Delegating to address(0) permanently locks funds.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _delegate(address _vault, address _from, address _to) internal {
    address _currentDelegate = _delegateOf(_vault, _from);
    delegates[_vault][_from] = _to;
    
    _transferDelegateBalance(
        _vault,
        _currentDelegate,
        _to, // If _to is address(0), funds are lost!
        uint96(userObservations[_vault][_from].details.balance)
    );
}
```

**Impact**: Users lose all funds when attempting to reset delegation.

**Mitigation**: Prevent delegation to address(0).

### 274. Collateralization Check Timing (PoolTogether H-07)
**Pattern**: Collateralization checked at function start instead of end.

**Vulnerable Code Example** (PoolTogether):
```solidity
function mintYieldFee(uint256 _shares, address _recipient) external {
    _requireVaultCollateralized(); // Check at start
    
    _yieldFeeTotalSupply -= _shares;
    _mint(_recipient, _shares);
    // Vault may be under-collateralized now!
}
```

**Impact**: Operations can leave vault under-collateralized.

**Mitigation**: Move collateralization check to end of state-changing functions.

### 275. Reserve Accounting Bypass (PoolTogether H-08)
**Pattern**: Direct reserve increases don't update accounted balance.

**Vulnerable Code Example** (PoolTogether):
```solidity
function increaseReserve(uint104 _amount) external {
    _reserve += _amount;
    prizeToken.safeTransferFrom(msg.sender, address(this), _amount);
    // accountedBalance not updated!
}

function contributePrizeTokens(address _prizeVault, uint256 _amount) external {
    uint256 _deltaBalance = prizeToken.balanceOf(address(this)) - _accountedBalance();
    // Can steal reserve injections!
}
```

**Impact**: Vaults can steal reserve contributions, double-counting prize tokens.

**Mitigation**: Track reserve injections in accounted balance calculation.

### 276. ERC4626 Vault Compatibility (PoolTogether H-09)
**Pattern**: Using maxWithdraw for exchange rate can cause losses with certain vault types.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _currentExchangeRate() internal view returns (uint256) {
    uint256 _withdrawableAssets = _yieldVault.maxWithdraw(address(this));
    // Some vaults return less than actual balance!
}
```

**Impact**: Exchange rate manipulation with vaults that have borrowing mechanisms or withdrawal limits.

**Mitigation**: Document incompatible vault types or use different calculation method.

### 277. Hook-Based Attack Vectors (PoolTogether M-02)
**Pattern**: User-controlled hooks enable various attack vectors.

**Vulnerable Code Example** (PoolTogether):
```solidity
function setHooks(VaultHooks memory hooks) external {
    _hooks[msg.sender] = hooks; // No validation!
    emit SetHooks(msg.sender, hooks);
}

function _claimPrize(...) internal returns (uint256) {
    if (hooks.useBeforeClaimPrize) {
        recipient = hooks.implementation.beforeClaimPrize(_winner, _tier, _prizeIndex);
        // Can revert, manipulate state, or grief!
    }
}
```

**Impact**: Griefing attacks, reentrancy, unauthorized external calls, DoS.

**Mitigation**: Add gas limits and error handling for hook calls.

### 278. TWAB Time Range Safety (PoolTogether M-03)
**Pattern**: Missing time range validation for historical balance queries.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _getVaultUserBalanceAndTotalSupplyTwab(address _vault, address _user, uint256 _drawDuration) internal view returns (uint256 twab, uint256 twabTotalSupply) {
    uint32 _endTimestamp = uint32(_lastClosedDrawStartedAt + drawPeriodSeconds);
    uint32 _startTimestamp = uint32(_endTimestamp - _drawDuration * drawPeriodSeconds);
    
    twab = twabController.getTwabBetween(_vault, _user, _startTimestamp, _endTimestamp);
    // No isTimeRangeSafe check!
}
```

**Impact**: Inaccurate TWAB calculations affecting prize distribution.

**Mitigation**: Add isTimeRangeSafe validation before getTwabBetween calls.

### 279. Missing Maximum Mint Validation (PoolTogether M-04)
**Pattern**: deposit() doesn't check if resulting shares exceed maxMint.

**Vulnerable Code Example** (PoolTogether):
```solidity
function deposit(uint256 _assets, address _receiver) public returns (uint256) {
    if (_assets > maxDeposit(_receiver)) revert DepositMoreThanMax(_receiver, _assets, maxDeposit(_receiver));
    // No check if shares > maxMint!
}
```

**Impact**: Can mint shares exceeding protocol limits with under-collateralized vaults.

**Mitigation**: Add maxMint validation in deposit function.

### 280. Sponsorship Address Balance Invariant (PoolTogether M-05)
**Pattern**: Transfers to SPONSORSHIP_ADDRESS break total supply accounting.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _transferBalance(...) internal {
    if (_to != address(0)) {
        _increaseBalances(_vault, _to, _amount, _isToDelegate ? _amount : 0);
        
        if (!_isToDelegate && _toDelegate != SPONSORSHIP_ADDRESS) {
            _increaseBalances(_vault, _toDelegate, 0, _amount);
        }
        // SPONSORSHIP_ADDRESS balance increases but total doesn't!
    }
}
```

**Impact**: Sum of individual balances exceeds total supply, skewing odds.

**Mitigation**: Disallow transfers to SPONSORSHIP_ADDRESS.

### 281. Draw Manager Front-Running (PoolTogether M-06)
**Pattern**: Anyone can set draw manager if not already set.

**Vulnerable Code Example** (PoolTogether):
```solidity
function setDrawManager(address _drawManager) external {
    if (drawManager != address(0)) {
        revert DrawManagerAlreadySet();
    }
    drawManager = _drawManager; // No access control!
    emit DrawManagerSet(_drawManager);
}
```

**Impact**: Malicious draw manager can withdraw reserves and manipulate draws.

**Mitigation**: Add access control or set in constructor only.

### 282. Math Library Pow() Inconsistencies (PoolTogether M-07)
**Pattern**: PRBMath pow() function returns inconsistent values.

**Impact**: Incorrect tier odds and draw accumulator calculations.

**Mitigation**: Upgrade to PRBMath v4 and Solidity 0.8.19.

### 283. CREATE1 Deployment Front-Running (PoolTogether M-08)
**Pattern**: Vault deployments vulnerable to front-running.

**Vulnerable Code Example** (PoolTogether):
```solidity
function deployVault(...) external returns (address) {
    vault = address(new Vault{salt: salt}(...)); // CREATE1 deployment
}
```

**Impact**: Attacker can deploy malicious vault at same address.

**Mitigation**: Use CREATE2 with vault config as salt.

### 284. Incentive Cap at Minimum Prize (PoolTogether M-09)
**Pattern**: Claimer fees capped at smallest prize size.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _computeMaxFee(uint8 _tier, uint8 _numTiers) internal view returns (uint256) {
    uint8 _canaryTier = _numTiers - 1;
    if (_tier != _canaryTier) {
        return _computeMaxFee(prizePool.getTierPrizeSize(_canaryTier - 1));
    }
}
```

**Impact**: No incentive to claim large prizes when gas costs exceed minimum prize.

**Mitigation**: Base max fee on actual tier prize size.

### 285. Prize Size Downcast Overflow (PoolTogether M-10)
**Pattern**: Unsafe downcast from uint256 to uint96 for prize sizes.

**Vulnerable Code Example** (PoolTogether):
```solidity
tier.prizeSize = uint96(
    _computePrizeSize(
        _tier,
        _numberOfTiers,
        fromUD34x4toUD60x18(tier.prizeTokenPerShare),
        fromUD34x4toUD60x18(prizeTokenPerShare)
    )
);
```

**Impact**: Incorrect prize sizes when value exceeds uint96.

**Mitigation**: Add safe casting with overflow checks.

### 286. Permit Function DoS (PoolTogether M-11)
**Pattern**: mintWithPermit vulnerable to front-running.

**Vulnerable Code Example** (PoolTogether):
```solidity
function mintWithPermit(uint256 _shares, address _receiver, uint256 _deadline, uint8 _v, bytes32 _r, bytes32 _s) external {
    uint256 _assets = _beforeMint(_shares, _receiver);
    _permit(IERC20Permit(asset()), msg.sender, address(this), _assets, _deadline, _v, _r, _s);
    // _assets can change between signature and execution!
}
```

**Impact**: Function unusable due to exchange rate manipulation.

**Mitigation**: Remove mintWithPermit functionality.

### 287. Tier Odds Calculation Error (PoolTogether M-12)
**Pattern**: Highest standard tier doesn't have odds of 1.

**Vulnerable Code Example** (PoolTogether):
```solidity
// Canary tier has odds of 1
SD59x18 internal constant TIER_ODDS_2_3 = SD59x18.wrap(1000000000000000000);
// But highest standard tier doesn't!
SD59x18 internal constant TIER_ODDS_1_3 = SD59x18.wrap(52342392259021369);
```

**Impact**: Prize distribution doesn't match intended design.

**Mitigation**: Recalculate tier odds with correct algorithm.

### 288. Observation Creation Manipulation (PoolTogether M-13)
**Pattern**: Users can prevent new observation creation to manipulate averages.

**Vulnerable Code Example** (PoolTogether):
```solidity
if (currentPeriod == 0 || currentPeriod > newestObservationPeriod) {
    return (
        uint16(RingBufferLib.wrap(_accountDetails.nextObservationIndex, MAX_CARDINALITY)),
        newestObservation,
        true
    );
}
// Small frequent deposits keep periods equal, preventing new observations
```

**Impact**: Users can manipulate their average balance for draws.

**Mitigation**: Align TWAB queries on period boundaries.

### 289. Tier Expansion with Single Canary Claim (PoolTogether M-14)
**Pattern**: One canary claim causes tier count to increase.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _computeNextNumberOfTiers(uint8 _numTiers) internal view returns (uint8) {
    uint8 _nextNumberOfTiers = largestTierClaimed + 2;
    
    if (_nextNumberOfTiers >= _numTiers && /* threshold checks */) {
        _nextNumberOfTiers = _numTiers + 1;
    }
    
    return _nextNumberOfTiers; // Always returns increased count!
}
```

**Impact**: Rapid tier expansion diluting prizes.

**Mitigation**: Only expand tiers when thresholds are met.

### 290. Tier Maintenance DoS (PoolTogether M-15)
**Pattern**: Single user can keep unprofitable tiers active.

**Attack**: Claim one prize from highest tier at a loss to maintain tier count.

**Impact**: Prevents tier reduction, keeping prizes unprofitable to claim.

**Mitigation**: Improve tier shrinking logic.

### 291. Maximum Tier Threshold Bypass (PoolTogether M-16)
**Pattern**: Threshold check skipped when reaching maximum tiers.

**Vulnerable Code Example** (PoolTogether):
```solidity
if (_nextNumberOfTiers >= MAXIMUM_NUMBER_OF_TIERS) {
    return MAXIMUM_NUMBER_OF_TIERS; // Skips threshold validation!
}
```

**Impact**: Adds 15th tier without meeting claim thresholds.

**Mitigation**: Always validate thresholds before tier expansion.

### 292. CREATE2 Front-Running Prevention (PoolTogether M-08 Mitigation)
**Pattern**: Using CREATE2 with deterministic addresses prevents front-running.

**Secure Implementation**:
```solidity
function deployVault(...) external returns (address vault) {
    bytes32 salt = keccak256(abi.encode(_name, _symbol, _yieldVault, _prizePool, _claimer, _yieldFeeRecipient, _yieldFeePercentage, _owner));
    vault = address(new Vault{salt: salt}(...));
}
```

**Impact**: Prevents malicious vault deployment at predicted addresses.

### 293. Vault Decimal Precision Loss (PoolTogether M-22)
**Pattern**: Loss of precision treated as vault loss.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _currentExchangeRate() internal view returns (uint256) {
    uint256 _withdrawableAssets = _yieldVault.maxWithdraw(address(this));
    // 1 wei precision loss triggers under-collateralized mode!
}
```

**Impact**: Normal precision loss blocks deposits.

**Mitigation**: Add 1 wei tolerance for precision loss.

### 294. ERC4626 View Function Compliance (PoolTogether M-23)
**Pattern**: maxDeposit/maxMint don't check yield vault limits.

**Vulnerable Code Example** (PoolTogether):
```solidity
function maxDeposit(address) public view virtual override returns (uint256) {
    return _isVaultCollateralized() ? type(uint96).max : 0;
    // Ignores _yieldVault.maxDeposit()!
}
```

**Impact**: Integration failures with protocols expecting ERC4626 compliance.

**Mitigation**: Return minimum of vault limit and yield vault limit.

### 295. Claimer Prize Claim Front-Running (PoolTogether M-24)
**Pattern**: Bots can be griefed by front-running last prize in batch.

**Vulnerable Code Example** (PoolTogether):
```solidity
function claimPrizes(...) external returns (uint256 totalFees) {
    vault.claimPrizes(tier, winners, prizeIndices, feePerClaim, _feeRecipient);
    // Reverts if any prize already claimed!
}
```

**Impact**: Claim bots lose gas costs, reduced claiming incentive.

**Mitigation**: Allow silent failure for already claimed prizes.

### 296. Permit Caller Restriction (PoolTogether M-25)
**Pattern**: Permit functions only work for direct signers.

**Vulnerable Code Example** (PoolTogether):
```solidity
function depositWithPermit(...) external returns (uint256) {
    _permit(IERC20Permit(asset()), msg.sender, address(this), _assets, _deadline, _v, _r, _s);
    // Always uses msg.sender, not _receiver!
}
```

**Impact**: Contracts cannot deposit on behalf of users with permits.

**Mitigation**: Use _receiver as permit owner.

### 297. Silent Transfer Overflow (PoolTogether M-26)
**Pattern**: Transfer amounts silently truncated to uint96.

**Vulnerable Code Example** (PoolTogether):
```solidity
function _transfer(address _from, address _to, uint256 _shares) internal virtual override {
    _twabController.transfer(_from, _to, uint96(_shares)); // Silent truncation!
}
```

**Impact**: Accounting errors in integrated protocols.

**Mitigation**: Use SafeCast for all conversions.

### 298. Canary Claim Fee Exclusion (PoolTogether M-27)
**Pattern**: Fee calculations don't include canary claims.

**Vulnerable Code Example** (PoolTogether):
```solidity
uint96 feePerClaim = uint96(
    _computeFeePerClaim(
        _computeMaxFee(tier, prizePool.numberOfTiers()),
        claimCount,
        prizePool.claimCount() // Should include canaryClaimCount!
    )
);
```

**Impact**: Incorrect fee calculations for claimers.

**Mitigation**: Include canary claims in total count.

### 299. Initial Deposit Manipulation in ERC4626 AutoRollers (Sense)
**Pattern**: First depositor inflates share price by depositing large amounts, forcing subsequent depositors to contribute disproportionate values.

**Vulnerable Code Example** (Sense):
```solidity
function previewMint(uint256 shares) public view virtual returns (uint256) {
    uint256 supply = totalSupply;
    return supply == 0 ? shares : shares.mulDivUp(totalAssets(), supply);
}
```

**Impact**: Future depositors forced to deposit huge values, effectively DoSing the vault for regular users.

**Mitigation**:
- Require minimum initial mint with portion burned or sent to DAO
- Deploy with initial seed liquidity
- Virtual shares offset

### 300. Public Approval Function DoS (Sense)
**Pattern**: Unprotected public `approve()` functions can be front-run to set allowance to 0.

**Vulnerable Code Example** (Sense):
```solidity
function approve(ERC20 token, address to, uint256 amount) public payable {
    token.safeApprove(to, amount); // Anyone can call with amount = 0
}
```

**Impact**: Complete DoS of deposit/mint functionality.

**Mitigation**: Restrict approve() to authorized callers or only allow max approvals.

### 301. Yield Theft Through Exit Mechanisms (Sense)
**Pattern**: Exit functions that combine yield-bearing positions can accidentally transfer entire protocol yield to single user.

**Vulnerable Code Example** (Sense):
```solidity
function eject(...) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {
    (excessBal, isExcessPTs) = _exitAndCombine(shares);
    _burn(owner, shares);
    
    // Transfers entire balance including yield from all YTs!
    assets = asset.balanceOf(address(this));
    asset.transfer(receiver, assets);
}
```

**Impact**: User receives yield from entire vault, not just their proportional share.

**Mitigation**: Calculate and transfer only user's proportional share of combined assets.

### 302. Series Creation Race Conditions (Sense)
**Pattern**: Multiple contracts creating series on same adapter can brick each other through maturity conflicts.

**Vulnerable Code Example** (Sense):
```solidity
function create(address adapter, uint256 maturity) external returns (address pool) {
    _require(pools[adapter][maturity] == address(0), Errors.POOL_ALREADY_EXISTS);
    // Reverts if another AutoRoller created series at same maturity
}
```

**Attack**: Create AutoRoller with different duration that produces conflicting maturity timestamps.

**Impact**: Original AutoRoller permanently bricked, cannot roll to new series.

**Mitigation**: Allow joining existing series or implement conflict resolution.

### 303. Admin Function Sandwich Attack in Concentrated Liquidity Vaults (Beefy)
**Pattern**: Admin functions that redeploy liquidity without calm period checks can be sandwiched to drain funds.

**Vulnerable Code Example** (Beefy):
```solidity
function setPositionWidth(int24 _width) external onlyOwner {
    _claimEarnings();
    _removeLiquidity();
    positionWidth = _width;
    _setTicks(); // Gets current tick without calm check
    _addLiquidity(); // Deploys at manipulated price
}

function unpause() external onlyManager {
    _isPaused = false;
    _setTicks(); // Gets current tick without calm check
    _addLiquidity(); // Deploys at manipulated price
}
```

**Attack Flow**:
1. Attacker front-runs with large swap pushing price up
2. Admin transaction executes, deploying liquidity at inflated range
3. Attacker back-runs, selling into deployed liquidity at inflated prices

**Impact**: Complete drainage of protocol funds ($1.2M+ demonstrated).

**Mitigation**: Add `onlyCalmPeriods` modifier to admin functions or to `_setTicks`.

### 304. Missing Slippage Protection in Fee Swaps (Beefy)
**Pattern**: Protocol fee swaps with `amountOutMinimum: 0` vulnerable to MEV.

**Vulnerable Code Example** (Beefy):
```solidity
function swap(address _router, bytes memory _path, uint256 _amountIn) internal returns (uint256 amountOut) {
    IUniswapRouterV3.ExactInputParams memory params = IUniswapRouterV3.ExactInputParams({
        path: _path,
        recipient: address(this),
        deadline: block.timestamp,
        amountIn: _amountIn,
        amountOutMinimum: 0 // No slippage protection!
    });
}
```

**Impact**: Reduced protocol fees due to sandwich attacks.

**Mitigation**: Calculate minimum output off-chain and pass as parameter.

### 305. Fee Accumulation from Rounding Errors (Beefy)
**Pattern**: Division rounding in fee distribution causes permanent token accumulation.

**Vulnerable Code Example** (Beefy):
```solidity
function _chargeFees() private {
    uint256 callFeeAmount = nativeEarned * fees.call / DIVISOR;
    IERC20(native).safeTransfer(_callFeeRecipient, callFeeAmount);
    
    uint256 beefyFeeAmount = nativeEarned * fees.beefy / DIVISOR;
    IERC20(native).safeTransfer(beefyFeeRecipient, beefyFeeAmount);
    
    uint256 strategistFeeAmount = nativeEarned * fees.strategist / DIVISOR;
    IERC20(native).safeTransfer(strategist, strategistFeeAmount);
    // Remainder stuck due to rounding
}
```

**Impact**: Cumulative loss of fees permanently stuck in contract.

**Mitigation**: Send remainder to one recipient:
```solidity
uint256 beefyFeeAmount = nativeEarned - callFeeAmount - strategistFeeAmount;
```

### 306. Stale Allowances on Router Updates (Beefy)
**Pattern**: Token allowances not removed when router addresses are updated.

**Vulnerable Code Example** (Beefy):
```solidity
function setUnirouter(address _unirouter) external onlyOwner {
    unirouter = _unirouter; // Old router keeps allowances!
    emit SetUnirouter(_unirouter);
}

function _giveAllowances() private {
    IERC20(lpToken0).forceApprove(unirouter, type(uint256).max);
    IERC20(lpToken1).forceApprove(unirouter, type(uint256).max);
}
```

**Impact**: Old router can continue spending protocol tokens.

**Mitigation**: Override `setUnirouter` to remove allowances before update.

### 307. Calm Period MIN/MAX Tick Edge Cases (Beefy)
**Pattern**: `onlyCalmPeriods` check fails at tick boundaries.

**Vulnerable Code Example** (Beefy):
```solidity
function _onlyCalmPeriods() private view {
    int24 tick = currentTick();
    int56 twapTick = twap();
    
    if(twapTick - maxTickDeviationNegative > tick || // Can underflow below MIN_TICK
       twapTick + maxTickDeviationPositive < tick) revert NotCalm();
}
```

**Impact**: DoS of deposits, withdrawals, and harvests at extreme prices.

**Mitigation**:
```solidity
int56 minCalmTick = max(twapTick - maxTickDeviationNegative, MIN_TICK);
int56 maxCalmTick = min(twapTick + maxTickDeviationPositive, MAX_TICK);
```

### 308. Share Price Manipulation via Recycled Deposits (Beefy)
**Pattern**: First depositor can massively inflate share count through deposit/withdrawal cycles.

**Attack Flow**:
1. First depositor deposits initial amount
2. Repeatedly: withdraw all → deposit all
3. Share count inflates with each cycle

**Impact**: While share count inflates, no direct theft mechanism found.

**Mitigation**: Rework share calculation logic to prevent recycling benefits.

### 309. Concentrated Liquidity Tick Update Gaps (Beefy)
**Pattern**: Missing tick updates before liquidity deployment in certain paths.

**Vulnerable Code Example** (Beefy):
```solidity
function withdraw() external {
    _removeLiquidity();
    // Missing _setTicks() here!
    _addLiquidity(); // Uses stale tick data
}
```

**Impact**: Non-optimal liquidity positions, reduced LP rewards.

**Mitigation**: Ensure `_setTicks()` called before all `_addLiquidity()` calls.

### 310. Zero Share Minting Despite Positive Deposits (Beefy)
**Pattern**: Rounding and minimum share subtraction can result in zero shares.

**Vulnerable Code Example** (Beefy):
```solidity
function deposit() external {
    uint256 shares = _amount1 + (_amount0 * price / PRECISION);
    if (_totalSupply == 0 && shares > 0) {
        shares = shares - MINIMUM_SHARES; // Can make shares = 0!
        _mint(address(0), MINIMUM_SHARES);
    }
    _mint(receiver, shares); // Mints 0 shares!
}
```

**Impact**: Users lose deposited tokens with no shares received.

**Mitigation**: Add zero share check after all calculations.

### 311. Price Calculation Overflow for Large sqrtPriceX96 (Beefy)
**Pattern**: Square operation in price calculation overflows for valid Uniswap prices.

**Vulnerable Code Example** (Beefy):
```solidity
function price(uint160 sqrtPriceX96) internal pure returns (uint256 _price) {
    _price = FullMath.mulDiv(uint256(sqrtPriceX96) ** 2, PRECISION, (2 ** 192));
    // Overflows for sqrtPriceX96 > 3.4e38
}
```

**Impact**: DoS of deposits and other price-dependent functions.

**Mitigation**: Refactor to avoid intermediate overflow.

### 312. Block.timestamp as Deadline Provides No Protection (Beefy)
**Pattern**: Using current timestamp as deadline in swaps.

**Vulnerable Code Example** (Beefy):
```solidity
IUniswapRouterV3.ExactInputParams memory params = IUniswapRouterV3.ExactInputParams({
    deadline: block.timestamp, // Always passes!
    // ...
});
```

**Impact**: No protection against transaction delays or validator manipulation.

**Mitigation**: Accept deadline as parameter from caller.

### 313. Concentrated Liquidity pool.slot0 Manipulation Risks (Beefy)
**Pattern**: Reading current price/tick from slot0 enables various attacks.

**Usage Points**:
- Setting liquidity ranges
- Calculating deposit shares
- Price conversions

**Impact**: Despite calm period checks, any implementation gaps enable draining attacks.

**Mitigation**: Maintain strict calm period enforcement, consider TWAP for critical operations.

### 314. Storage Gaps Missing in Upgradeable Contracts (Beefy)
**Pattern**: Upgradeable contracts without storage gaps risk slot collisions.

**Vulnerable Code Example** (Beefy):
```solidity
contract StratFeeManagerInitializable is Initializable, OwnableUpgradeable {
    // State variables but no __gap!
}
```

**Impact**: Storage collision on upgrades can corrupt child contract state.

**Mitigation**: Add storage gap: `uint256[50] private __gap;`

### 315. Upgradeable Contracts Missing disableInitializers (Beefy)
**Pattern**: Implementation contracts can be initialized when they shouldn't be.

**Vulnerable Code Example** (Beefy):
```solidity
contract StrategyPassiveManagerUniswap is StratFeeManagerInitializable {
    // No constructor calling _disableInitializers()!
}
```

**Mitigation**:
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

### 316. Owner Rug-Pull via Calm Period Parameter Manipulation (Beefy)
**Pattern**: Owner can disable protection mechanisms to drain funds.

**Attack Flow**:
1. Owner calls `setDeviation` with large values or `setTwapInterval(1)`
2. Manipulate pool price via flash loan
3. Deposit at inflated share price
4. Withdraw at normal price for profit

**Mitigation**: Enforce minimum safe parameter bounds.

### 317. Withdrawal Returns Zero Tokens for Positive Shares (Beefy)
**Pattern**: Rounding in withdrawal calculation can return nothing.

**Vulnerable Code Example** (Beefy):
```solidity
function withdraw(uint256 _shares) external {
    uint256 _amount0 = (_bal0 * _shares) / _totalSupply; // Can round to 0
    uint256 _amount1 = (_bal1 * _shares) / _totalSupply; // Can round to 0
}
```

**Mitigation**: Revert if both amounts are zero.

### 318. Permanent Token Lock from Donated Shares (Beefy)
**Pattern**: First depositor's donated shares create permanently locked tokens.

**Mechanism**: `MINIMUM_SHARES` sent to address(0) represent tokens that can never be withdrawn.

**Mitigation**: Add end-of-life function to recover when `totalSupply == MINIMUM_SHARES`.

### 319. Multi-Market Deposit Coordination Failure (Silo M-01)
**Pattern**: Vault attempts to deposit entire amount to each market without checking individual market limits.

**Vulnerable Code Example** (Silo):
```solidity
function _supplyERC4626(uint256 _assets) internal virtual {
    for (uint256 i; i < supplyQueue.length; ++i) {
        IERC4626 market = supplyQueue[i];
        uint256 toSupply = UtilsLib.min(UtilsLib.zeroFloorSub(supplyCap, supplyAssets), _assets);
        
        if (toSupply != 0) {
            try market.deposit(toSupply, address(this)) { // Reverts if toSupply > market.maxDeposit!
                _assets -= toSupply;
            } catch {}
        }
    }
}
```

**Impact**: Deposits fail even when sufficient space exists across multiple markets.

**Mitigation**: Check market.maxDeposit before attempting deposit:
```solidity
toSupply = Math.min(market.maxDeposit(address(this)), toSupply);
```

### 320. Reward Accrual Timing Error During Transfers (Silo M-02)
**Pattern**: Transfer hooks claim rewards without first updating totalSupply through fee accrual.

**Vulnerable Code Example** (Silo):
```solidity
function _update(address _from, address _to, uint256 _value) internal virtual override {
    _claimRewards(); // Claims without updating totalSupply first!
    super._update(_from, _to, _value);
}
```

**Impact**: Incorrect reward distribution due to stale totalSupply.

**Mitigation**: Add _accrueFee() before _claimRewards() in transfer flow.

### 321. Market Removal DOS for Zero-Reverting Tokens (Silo M-03)
**Pattern**: Tokens that revert on zero approval prevent market removal.

**Vulnerable Code Example** (Silo):
```solidity
function setCap(...) external {
    if (_supplyCap > 0) {
        approveValue = type(uint256).max;
    }
    // approveValue remains 0 for cap = 0
    
    IERC20(_asset).forceApprove(address(_market), approveValue); // Reverts for BNB!
}
```

**Impact**: Markets with zero-reverting tokens cannot be removed.

**Mitigation**: Set approveValue to 1 instead of 0 when removing markets.

### 322. Missing Slippage Protection in Core Operations (Silo M-04)
**Pattern**: No user-specified slippage tolerance in deposit/withdraw/redeem functions.

**Vulnerable Code Example** (Silo):
```solidity
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    // No minShares parameter!
    shares = previewDeposit(assets);
    _deposit(msg.sender, receiver, assets, shares);
}
```

**Impact**: Users vulnerable to sandwich attacks and unfavorable price movements.

**Mitigation**: Add minShares/minAssets parameters to protect users.

### 323. Fee Share Minting Order Causing Reward Loss (Silo M-05)
**Pattern**: Fee shares minted after reward distribution, missing current period rewards.

**Vulnerable Code Example** (Silo):
```solidity
function claimRewards() public virtual {
    _updateLastTotalAssets(_accrueFee()); // Mints fee shares
    _claimRewards(); // But rewards already distributed in _accrueFee!
}

function _accrueFee() internal virtual returns (uint256 newTotalAssets) {
    if (feeShares != 0) _mint(feeRecipient, feeShares); // Triggers _update
}

function _update(address _from, address _to, uint256 _value) internal virtual override {
    _claimRewards(); // Distributes rewards before fee shares are minted!
    super._update(_from, _to, _value);
}
```

**Impact**: Fee recipient permanently loses rewards for each interest accrual period.

**Mitigation**: Implement flag-based logic to handle fee share minting specially.

### 324. Deflation Attack Through Market Rounding (Silo M-06)
**Pattern**: Market rounding can be exploited to deflate share price until near overflow.

**Vulnerable Code Example** (Silo):
```solidity
// First deposit of 1 wei
market.deposit(1, address(this)); // Market rounds to 0, returns no shares
// Next deposit calculates shares as:
// 1 wei * (10**decimalsOffset + 1) / (0 + 1) = 2 * 10**decimalsOffset shares
// Repeated 1 wei deposits double totalSupply each time!
```

**Impact**: Share price deflation enabling vault bricking or reward monopolization.

**Mitigation**: Set virtual assets equal to virtual shares (10**DECIMALS_OFFSET).

### 325. Unchecked 2-Step Ownership Transfer (Dacian)
**Pattern**: Second step of ownership transfer doesn't verify first step was initiated.

**Vulnerable Code Example**:
```solidity
function completeNodeOwnerTransfer(uint64 id) external {
    uint64 newOwner = pendingNodeOwnerTransfers[id]; // 0 if not started
    uint64 accountId = accounts.resolveId(msg.sender); // 0 if not registered
    
    if (newOwner != accountId) revert NotAuthorizedForNode();
    
    nodes[id].owner = newOwner; // Sets to 0!
    delete pendingNodeOwnerTransfers[id];
}
```

**Impact**: Attacker can brick node ownership by setting owner to zero.

**Mitigation**: Require newOwner != 0 or validate transfer was initiated.

### 326. Unexpected Matching Inputs (Dacian)
**Pattern**: Functions assume different inputs but fail catastrophically with identical inputs.

**Vulnerable Code Example**:
```solidity
function _getTokenIndexes(IERC20 t1, IERC20 t2) internal pure returns (uint i, uint j) {
    for (uint k; k < _tokens.length; ++k) {
        if (t1 == _tokens[k]) i = k;
        else if (t2 == _tokens[k]) j = k; // Never executes if t1==t2!
    }
}
```

**Impact**: Returns (i, 0) when t1==t2, breaking invariants and enabling fund drainage.

**Mitigation**: Add validation: require(t1 != t2) or handle identical inputs properly.

### 327. Unexpected Empty Input Arrays (Dacian)
**Pattern**: Functions assume non-empty arrays, allowing validation bypass.

**Vulnerable Code Example**:
```solidity
function verifyAndSend(SigData[] calldata signatures) external {
    for (uint i; i<signatures.length; i++) {
        // verify signatures
    }
    // Empty array skips verification!
    (bool sent,) = payable(msg.sender).call{value: 1 ether}("");
    require(sent, "Failed");
}
```

**Impact**: Complete bypass of signature verification.

**Mitigation**: Require signatures.length > 0 before processing.

### 328. Unchecked Return Values (Dacian)
**Pattern**: Critical functions' return values ignored, enabling state corruption.

**Vulnerable Code Example**:
```solidity
function commitCollateral(uint loanId, address token, uint amount) external {
    CollateralInfo storage collateral = _loanCollaterals[loanId];
    
    collateral.collateralAddresses.add(token); // Returns false if already exists!
    collateral.collateralInfo[token] = amount; // Overwrites existing amount!
}
```

**Impact**: Borrowers can reduce collateral to 0 after loan approval.

**Mitigation**: Always check return values: require(collateral.collateralAddresses.add(token), "Already exists");

### 329. Rounding Down to Zero (Enhanced)
**Pattern**: Division in Solidity rounds down, which can result in critical values becoming zero, especially with small numbers.

**Vulnerable Code Example (Cooler)**:
```solidity
function errorRepay(uint repaid) external {
    // If repaid small enough, decollateralized will round down to 0
    uint decollateralized = loanCollateral * repaid / loanAmount;
    
    loanAmount     -= repaid;
    loanCollateral -= decollateralized;
}
```

**Impact**: Loans can be repaid without reducing collateral, allowing borrowers to extract value.

**Mitigation**:
```solidity
function correctRepay(uint repaid) external {
    uint decollateralized = loanCollateral * repaid / loanAmount;
    
    // Don't allow loan repayment without deducting from collateral
    if(decollateralized == 0) { revert("Round down to zero"); }
    
    loanAmount     -= repaid;
    loanCollateral -= decollateralized;
}
```

**Detection Heuristics**:
- Look for divisions where the result is used to update critical state
- Check if small input values can cause rounding to zero
- Consider whether zero results break protocol invariants

### 330. No Precision Scaling (Enhanced)
**Pattern**: Combining amounts of tokens with different decimal precision without proper scaling.

**Vulnerable Code Example (Notional)**:
```solidity
function errorGetWeightedBalance(...) external view returns (uint256 primaryAmount) {
    uint256 primaryBalance   = token1Amount * lpPoolTokens / poolTotalSupply;
    uint256 secondaryBalance = token2Amount * lpPoolTokens / poolTotalSupply;
    
    uint256 secondaryAmountInPrimary = secondaryBalance * lpPoolTokensPrecision / oraclePrice;
    
    // Adding balances with different precisions!
    primaryAmount = (primaryBalance + secondaryAmountInPrimary) * token1Precision / lpPoolTokensPrecision;
}
```

**Impact**: Dramatic undervaluation of LP tokens by ~50% in DAI/USDC pools.

**Mitigation**:
```solidity
function correctGetWeightedBalance(...) external view returns (uint256 primaryAmount) {
    uint256 primaryBalance   = token1Amount * lpPoolTokens / poolTotalSupply;
    uint256 secondaryBalance = token2Amount * lpPoolTokens / poolTotalSupply;
    
    // Scale secondary token to primary token's precision first
    secondaryBalance = secondaryBalance * token1Precision / token2Precision;
    
    uint256 secondaryAmountInPrimary = secondaryBalance * lpPoolTokensPrecision / oraclePrice;
    primaryAmount = primaryBalance + secondaryAmountInPrimary;
}
```

### 331. Excessive Precision Scaling (Enhanced)
**Pattern**: Applying precision scaling multiple times to already-scaled values.

**Impact**: Token amounts become excessively inflated, breaking calculations.

**Detection**: Trace token amount flows through functions to identify repeated scaling operations.

### 332. Mismatched Precision Scaling (Enhanced)
**Pattern**: Different modules using different precision assumptions (decimals vs 1e18).

**Vulnerable Code Example (Yearn)**:
```solidity
// Vault.vy uses token decimals
def pricePerShare() -> uint256:
    return self._shareValue(10 ** self.decimals)

// YearnYield uses hardcoded 1e18
function getTokensForShares(uint256 shares) public view returns (uint256) {
    amount = IyVault(liquidityToken[asset]).getPricePerFullShare().mul(shares).div(1e18);
}
```

**Impact**: Incorrect calculations for non-18 decimal tokens.

**Mitigation**: Ensure consistent precision handling across all modules.

### 333. Rounding Leaks Value From Protocol (Enhanced)
**Pattern**: Fee calculations that round in favor of users instead of the protocol.

**Vulnerable Code Example (SudoSwap)**:
```solidity
// Rounding down favors traders
protocolFee = outputValue.mulWadDown(protocolFeeMultiplier);
tradeFee = outputValue.mulWadDown(feeMultiplier);
```

**Mitigation**:
```solidity
// Round up to favor protocol
protocolFee = outputValue.mulWadUp(protocolFeeMultiplier);
tradeFee = outputValue.mulWadUp(feeMultiplier);
```

**Impact**: Systematic value leakage from protocol to traders over time.

### 334. Liquidation Timing Vulnerabilities
**Pattern**: Complex vulnerabilities around when and how liquidations can occur.

**Key Sub-Patterns**:
- **Liquidation Before Default**: Borrowers liquidated before missing payments
- **Grace Period Absence**: No recovery time after unpausing
- **Partial Liquidation Gaming**: Using partial liquidations to avoid bad debt
- **Whale Position Blocking**: Large positions impossible to liquidate without flash loans
- **Immediate Post-Resume Liquidation**: Liquidation bots advantage after unpause

**Detection Heuristics**:
- Verify liquidation only possible after actual default
- Check for grace periods after state changes
- Ensure partial liquidations properly handle bad debt
- Validate whale positions can be liquidated
- Test liquidation timing around pause/unpause cycles

### 335. Bad Debt and Incentive Misalignment
**Pattern**: Protocols failing to properly incentivize liquidations or handle insolvent positions.

**Key Sub-Patterns**:
- **No Liquidation Incentive**: Missing rewards for liquidators
- **Small Position Accumulation**: Dust positions not worth liquidating
- **Profitable Collateral Withdrawal**: Users removing collateral while in profit
- **Insurance Fund Depletion**: Bad debt exceeding insurance capacity
- **Fixed Bonus Reverts**: Liquidation failing when collateral < 110%

**Vulnerable Example**:
```solidity
// Fixed 10% bonus causes revert when user has < 110% collateral
uint256 bonusCollateral = (tokenAmountFromDebtCovered * LIQUIDATION_BONUS) / LIQUIDATION_PRECISION;
_redeemCollateral(collateral, tokenAmountFromDebtCovered + bonusCollateral, user, msg.sender);
```

**Mitigation**: Cap bonus to available collateral, implement dynamic incentives

### 336. Liquidation DoS Attack Vectors
**Pattern**: Various methods attackers use to prevent their own liquidation.

**Attack Vectors**:
- **Many Small Positions**: Gas exhaustion iterating positions
- **Front-Run Prevention**: Nonce increment, partial self-liquidation
- **Pending Action Blocking**: Withdrawals blocking liquidation
- **Malicious Callbacks**: ERC721/ERC777 revert on receive
- **Yield Vault Hiding**: Collateral in external protocols
- **Array Manipulation**: Corrupting position ordering

**Example**:
```solidity
// Attacker creates many positions to cause OOG
function getItemIndex(uint256[] memory items, uint256 item) internal pure returns (uint256) {
    for (uint256 i = 0; i < items.length; i++) { // OOG with many items
        if (items[i] == item) return i;
    }
}
```

### 337. Liquidation Calculation Errors
**Pattern**: Mathematical errors in liquidation reward and fee calculations.

**Common Issues**:
- **Decimal Precision Mismatches**: Debt/collateral decimal differences
- **Protocol Fee Miscalculation**: Fees based on seized amount not profit
- **Reward Scaling Errors**: Linear scaling breaking with multiple accounts
- **Interest Exclusion**: Not including accrued interest in calculations
- **Wrong Token Amounts**: Using internal amounts without scaling

**Example**:
```solidity
// Liquidator reward uses debt decimals (6) for collateral calculation (18)
uint256 liquidatorReward = Math.mulDivUp(
    debtPosition.futureValue, // 6 decimals
    state.feeConfig.liquidationRewardPercent,
    PERCENT
); // Result in wrong decimals for WETH collateral
```

### 338. Cross-Protocol Liquidation Issues
**Pattern**: Problems arising from liquidation mechanics across different collateral types.

**Key Issues**:
- **Liquidator Collateral Selection**: Choosing stable over volatile collateral
- **Health Score Degradation**: Liquidation making positions worse
- **Priority Order Corruption**: Wrong liquidation sequence
- **Multi-Collateral Calculations**: Incorrect aggregate health scores

**Mitigation**:
```solidity
// Validate borrower health improves after liquidation
uint256 healthBefore = calculateHealthScore(borrower);
// ... perform liquidation ...
uint256 healthAfter = calculateHealthScore(borrower);
require(healthAfter > healthBefore, "Liquidation must improve health");
```

### 339. Oracle Price Inversion (USSD)
**Pattern**: Using inverted base/rate tokens for oracle price calculations, causing massive pricing errors.

**Vulnerable Code Example**:
```solidity
// Uses WETH/DAI from Uniswap pool
uint256 DAIWethPrice = DAIEthOracle.quoteSpecificPoolsWithTimePeriod(
    1000000000000000000, // 1 Eth
    0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, // WETH (base)
    0x6B175474E89094C44Da98b954EedeAC495271d0F, // DAI (quote)
    pools,
    600
);

// But uses DAI/ETH from Chainlink
(, int256 price, , , ) = priceFeedDAIETH.latestRoundData();

// Averages incompatible price formats!
return (wethPriceUSD * 1e18) / ((DAIWethPrice + uint256(price) * 1e10) / 2);
```

**Impact**: Incorrect average calculation leads to wildly inaccurate prices.

**Mitigation**: Ensure both price sources use same base/quote order or invert one before averaging.

### 340. Logical Operator Errors (USSD)
**Pattern**: Using || instead of && in conditional checks, causing incorrect logic execution.

**Vulnerable Code Example**:
```solidity
// WRONG: Should be && to exclude DAI
if (collateral[i].token != uniPool.token0() || collateral[i].token != uniPool.token1()) {
    // Always true - will try to sell DAI even though it has no path
    IUSSD(USSD).UniV3SwapInput(collateral[i].pathsell, amountToSellUnits);
}
```

**Impact**: Attempts to sell DAI without a sell path, causing rebalancing to revert.

**Mitigation**: Use correct logical operators:
```solidity
if (collateral[i].token != uniPool.token0() && collateral[i].token != uniPool.token1())
```

### 341. Price Calculation Formula Errors (USSD)
**Pattern**: Incorrect mathematical formulas in price calculations for Uniswap V3.

**Vulnerable Code Example**:
```solidity
// When token0 is USSD
price = uint(sqrtPriceX96)*(uint(sqrtPriceX96))/(1e6) >> (96 * 2);
// Should multiply by 1e6, not divide!

// When token1 is USSD
price = uint(sqrtPriceX96)*(uint(sqrtPriceX96))*(1e18) >> (96 * 2);
// Should use 1e6, not 1e18!
```

**Impact**: Massive pricing errors affecting all rebalancing operations.

**Mitigation**: Use correct Uniswap V3 price calculation formulas per documentation.

### 342. Oracle Decimal Assumptions (USSD)
**Pattern**: Assuming fixed decimal values for oracle responses when they vary.

**Vulnerable Code Example**:
```solidity
// Assumes DAI/ETH oracle returns 8 decimals
return (wethPriceUSD * 1e18) / ((DAIWethPrice + uint256(price) * 1e10) / 2);
// But DAI/ETH actually returns 18 decimals!
```

**Impact**: 10^10 overvaluation of DAI price, allowing massive exploitation.

**Mitigation**: Check oracle decimals() or verify actual decimal count.

### 343. Uniswap V3 Slot0 Price Manipulation (USSD)
**Pattern**: Using instantaneous slot0 price instead of TWAP, enabling flash loan attacks.

**Vulnerable Code Example**:
```solidity
function getOwnValuation() public view returns (uint256 price) {
    (uint160 sqrtPriceX96,,,,,,) = uniPool.slot0();
    // Uses manipulatable spot price!
}
```

**Impact**: Attacker can manipulate price to trigger favorable rebalancing.

**Mitigation**: Use TWAP price over reasonable period (e.g., 30 minutes).

### 344. Missing Access Control on Critical Functions (USSD)
**Pattern**: Functions that mint/burn tokens lack proper access control.

**Vulnerable Code Example**:
```solidity
function mintRebalancer(uint256 amount) public override {
    _mint(address(this), amount); // Anyone can call!
}

function burnRebalancer(uint256 amount) public override {
    _burn(address(this), amount); // Anyone can call!
}
```

**Impact**: Attacker can mint up to max supply, manipulate totalSupply for rebalancing.

**Mitigation**: Add `onlyBalancer` modifier to restrict access.

### 345. Uniswap V3 Balance-Based Price Assumptions (USSD)
**Pattern**: Assuming pool token balances reflect price in concentrated liquidity.

**Vulnerable Code Example**:
```solidity
function getSupplyProportion() public view returns (uint256, uint256) {
    return (IERC20Upgradeable(USSD).balanceOf(uniPool), IERC20(DAI).balanceOf(uniPool));
}
// Balances don't represent price in Uniswap V3!
```

**Impact**: Rebalancing calculations completely incorrect, can cause underflow.

**Mitigation**: Use proper Uniswap V3 liquidity calculations, not raw balances.

### 346. Oracle Address Configuration Errors (USSD)
**Pattern**: Wrong contract addresses for critical oracles.

**Examples**:
- StableOracleWBTC using ETH/USD feed instead of BTC/USD
- StableOracleDAI with wrong DAIEthOracle address
- StableOracleDAI ethOracle set to address(0)
- StableOracleWBGL using pool address instead of oracle

**Impact**: Completely incorrect prices for all operations.

**Mitigation**: Verify all oracle addresses before deployment.

### 347. Oracle Price Unit Mismatch (USSD)
**Pattern**: Oracle prices denominated in wrong currency for intended use.

**Issue**: All oracles return USD prices but system expects DAI prices for peg maintenance.

**Attack Scenario**:
1. When DAI > $1, users mint USSD with DAI at inflated rate
2. Sell USSD for more DAI than deposited
3. System rebalances incorrectly, depleting collateral

**Impact**: Complete destruction of peg mechanism.

**Mitigation**: Convert all oracle prices to DAI denomination.

### 348. Rebalancing Underflow Vulnerabilities (USSD)
**Pattern**: Subtraction operations that can underflow during rebalancing.

**Vulnerable Code Example**:
```solidity
amountToBuyLeftUSD -= (IERC20Upgradeable(baseAsset).balanceOf(USSD) - amountBefore);
// Can underflow if actual swap returns more than expected
```

**Impact**: Rebalancing reverts, protocol becomes unable to maintain peg.

**Mitigation**: Check if result would underflow, cap at zero if needed.

### 349. Array Index Out of Bounds (USSD)
**Pattern**: Flutter index can exceed array bounds when collateral factor is high.

**Vulnerable Code Example**:
```solidity
for (flutter = 0; flutter < flutterRatios.length; flutter++) {
    if (cf < flutterRatios[flutter]) {
        break;
    }
}
// flutter can equal flutterRatios.length after loop

// Later accesses out of bounds:
if (collateralval * 1e18 / ownval < collateral[i].ratios[flutter]) {
```

**Impact**: Rebalancing always reverts when collateral factor exceeds all flutter ratios.

**Mitigation**: Check flutter < flutterRatios.length before array access.

### 350. Missing Collateral Asset Accounting (USSD)
**Pattern**: Removed collateral assets not included in collateral factor calculation.

**Vulnerable Code Example**:
```solidity
function removeCollateral(uint256 _index) public onlyControl {
    collateral[_index] = collateral[collateral.length - 1];
    collateral.pop();
    // Removed asset still held by contract but not counted!
}
```

**Impact**: Collateral factor underreported, affecting risk assessment.

**Mitigation**: Transfer removed collateral out or continue counting it.

### 351. DAI Collateral Handling Inconsistency (USSD)
**Pattern**: DAI as collateral not handled consistently in sell operations.

**Vulnerable Code Example**:
```solidity
// First branch handles DAI correctly
if (collateralval > amountToBuyLeftUSD) {
    if (collateral[i].pathsell.length > 0) {
        // Sell collateral
    } else {
        // Don't sell DAI
    }
} else {
    // Second branch missing DAI check!
    IUSSD(USSD).UniV3SwapInput(collateral[i].pathsell, ...);
}
```

**Impact**: Attempts to sell DAI without path cause revert.

**Mitigation**: Add pathsell.length check in else branch.

### 352. Wrapped Asset Depeg Risk (USSD)
**Pattern**: Using BTC price for WBTC without considering depeg possibility.

**Issue**: StableOracleWBTC uses BTC/USD feed, assumes 1:1 parity.

**Impact**: If WBTC depegs:
- Protocol values worthless WBTC at full BTC price
- Bad debt accumulation
- Continued minting against devalued collateral

**Mitigation**: Implement double oracle with WBTC/BTC ratio check.

### 353. Partial Collateral Sale Precision Loss (USSD)
**Pattern**: Complex division operations can round to zero for partial sales.

**Vulnerable Code Example**:
```solidity
uint256 amountToSellUnits = IERC20Upgradeable(collateral[i].token).balanceOf(USSD) *
    ((amountToBuyLeftUSD * 1e18 / collateralval) / 1e18) / 1e18;
// Multiple divisions can cause result to be 0
```

**Impact**: Rebalancing fails to sell any collateral when it should sell partial amounts.

**Mitigation**: Reorder operations to minimize precision loss.

### 354. Arbitrage Through Oracle Deviation (USSD)
**Pattern**: Minting at stale oracle prices enables risk-free profit.

**Attack**: When market price < oracle price by more than deviation threshold:
1. Mint USSD with collateral at oracle price
2. Sell for DAI at market price
3. Profit from difference

**Impact**: Continuous value extraction, depleting protocol collateral quality.

**Mitigation**: Add minting fee > max oracle deviation (e.g., 1%).

### 355. Missing Redeem Functionality (USSD)
**Pattern**: Only deposit or mint functions exists but no redeem or withdraw functions.

**Issue**: No way to burn USSD for underlying collateral, only one-way conversion.

**Impact**:
- Users cannot exit positions
- No arbitrage mechanism to maintain peg from below
- Breaks fundamental stablecoin mechanics

**Mitigation**: Implement redeem functionality so users can withdraw.

### 356. Synthetic Token Minter Depeg Vulnerability
**Pattern**: Minter contracts that perform 1:1 conversion between collateral assets and synthetic tokens without validating the current market value of the collateral.

**Vulnerable Code Example**:
```solidity
function mint(address to, uint256 amount) external {
   baseAsset.safeTransferFrom(msg.sender, address(this), amount);
   syntheticToken.mint(to, amount); // 1:1 conversion regardless of baseAsset value!
}
```

**Attack Scenarios**:
1. Depegged Wrapped Assets: User buys depegged wBTC at $40k, mints hBTC worth $100k
2. Wrong Asset Type: User deposits 1e6 USDC ($1), receives 1e6 hBTC ($100k+ value)
3. Cross-decimal Exploitation: Mixing 6-decimal stablecoins with 8-decimal BTC synthetics

**Impact**: Complete protocol insolvency as attackers drain liquidity pools with overvalued synthetic tokens.

**Mitigation**:
- Enforce decimal matching between collateral and synthetic
- Integrate price oracles (Chainlink) to verify collateral value
- Implement depeg protection with maximum deviation thresholds
- Add circuit breakers/pausing for emergency response
- Match synthetic tokens to equivalent base asset types

**Detection Heuristics**:
- Look for minter contracts with 1:1 conversion logic
- Check if price validation exists between input and output tokens
- Verify decimal handling for different asset types
- Search for assumptions about stable asset values
- Check for oracle integration in mint/burn functions

### 357. Permit2 Partial Transfer State Mismatch
**Pattern**: Protocol stores permitted amount in state while permit2 transfers a different requested amount, creating a mismatch between recorded and actual values.

**Vulnerable Code Example** (Redacted):
```solidity
function deposit(
    ISignatureTransfer.PermitTransferFrom memory permit,
    ISignatureTransfer.SignatureTransferDetails memory transferDetails,
    address depositor,
    DepositWitness memory witness,
    bytes memory signature
) external returns (bytes32 depositId) {
    // Stores permit.permitted.amount in state
    s_activeDeposits[depositId] = DepositInfo({
        amount: permit.permitted.amount,  // e.g., 1000 USDC
        // ... other fields
    });
    
    // But transfers transferDetails.requestedAmount
    i_permit2.permitWitnessTransferFrom(
        permit,
        transferDetails,  // Uses requestedAmount (can be 1 wei!)
        depositor,
        witnessHash,
        DEPOSIT_WITNESS_TYPE_STRING,
        signature
    );
}
```

**Attack Scenario**:
1. Attacker signs permit for full amount with themselves as controller
2. Sets `transferDetails.requestedAmount = 1 wei` before calling deposit
3. Protocol stores full amount but only receives 1 wei
4. Attacker withdraws/refunds full amount, draining protocol

**Impact**: Complete protocol drainage through state/transfer mismatch

**Mitigation**:
```solidity
require(
    permit.permitted.amount == transferDetails.requestedAmount,
    "Amount mismatch"
);
// Or have protocol create transferDetails internally
```

**Detection Heuristics**:
- Look for protocols using permit2 with separate storage of amounts
- Check if permitted amount and requested amount are validated to match
- Verify state updates match actual transferred amounts
- Search for scenarios where partial transfers could break invariants

**Cross References**: ID generation should include nonce to prevent #364.

### 358. Permit2 Witness Hash Computation Error
**Pattern**: Protocol computes witness hash using raw encoding instead of EIP-712 struct hash format required by Permit2.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Using raw keccak256 encoding
bytes32 witnessHash = keccak256(abi.encode(witness.requestId, witness.reserver, witness.releaser));

// CORRECT: Using EIP-712 struct hash
bytes32 witnessHash = keccak256(
    abi.encode(
        keccak256("DepositWitness(bytes32 requestId,address reserver,address releaser)"),
        witness.requestId,
        witness.reserver,
        witness.releaser
    )
);
```

**Impact**: Standard Permit2 signing libraries won't work, causing integration failures and temporary DoS for users expecting standard behavior.

**Mitigation**: Always use EIP-712 struct hash format when computing witness hashes for Permit2.

**Detection Heuristics**:
- Look for `permitWitnessTransferFrom` calls
- Check if witness hash uses `keccak256(abi.encode(...))` without type hash
- Verify witness hash follows EIP-712 struct encoding standards
- Compare against Uniswap Permit2 documentation examples

### 359. Permit2 Witness Type String Misconfiguration
**Pattern**: Incorrect or incomplete witness type string format when calling Permit2, missing required type definitions or format elements.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Missing witness prefix and TokenPermissions definition
string private constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness(bytes32 requestId,address reserver,address releaser)";

// CORRECT: Complete type string with all required components
string private constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness witness)DepositWitness(bytes32 requestId,address reserver,address releaser)TokenPermissions(address token,uint256 amount)";
```

**Impact**: Permit2 witness validation fails with standard signing tools, requiring custom implementations and causing integration issues.

**Mitigation**:
- Include the witness type name followed by ` witness)`
- Add all struct definitions including referenced types like `TokenPermissions`
- Follow exact format from Uniswap documentation

**Detection Heuristics**:
- Check all Permit2 witness type strings for completeness
- Verify format matches: `"TypeName witness)TypeDefinition...ReferencedTypeDefinitions..."`
- Ensure TokenPermissions definition is included when using PermitTransferFrom
- Compare against working implementations in other protocols

### 360. ERC1271 Signature Validation Bypass for DoS
**Pattern**: When depositIds or similar identifiers are derived solely from signatures, attackers can deploy malicious ERC1271 contracts that claim any signature is valid, enabling griefing attacks.

**Vulnerable Code Example** (Redacted):
```solidity
// VULNERABLE: DepositId only based on signature
depositId = keccak256(signature);

// Attacker deploys contract that always returns valid:
contract MaliciousERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e; // Always claims signature is valid
    }
}

// Attacker can:
// 1. Use victim's signature with their malicious contract as depositor
// 2. Modify parameters (like amount to 1 wei)
// 3. Front-run, blocking subsequent legitimate deposit since depositId already exists
```

**Attack Scenario**:
1. Victim publishes signature for legitimate operation
2. Attacker deploys ERC1271 contract that always validates
3. Attacker uses victim's signature with modified parameters
4. Creates record with same ID, blocking legitimate operation
5. Costs attacker minimal funds (1 wei) to grief

**Impact**: Complete DoS of protocol operations at negligible cost

**Mitigation**:
```solidity
// Include the signer/depositor in ID generation
depositId = keccak256(abi.encode(depositor, signature));
// Or validate depositor matches expected signer
```

**Detection Heuristics**:
- Look for IDs derived only from signatures
- Check if protocol accepts ERC1271 contract signatures
- Verify depositor/signer validation
- Search for griefing opportunities via signature replay
- Check if attackers can claim signatures with different parameters

**Cross References**: See also #364 for approved hash collision issues.

### 361. Permit2 Witness Hash Computation Error
**Pattern**: Computing witness hash using raw encoding instead of EIP-712 struct hash format required by Permit2.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Raw keccak256 encoding
bytes32 witnessHash = keccak256(abi.encode(witness.requestId, witness.reserver, witness.releaser));

// CORRECT: EIP-712 struct hash with type hash first
bytes32 witnessHash = keccak256(
    abi.encode(
        keccak256("DepositWitness(bytes32 requestId,address reserver,address releaser)"),
        witness.requestId,
        witness.reserver,
        witness.releaser
    )
);
```

**Impact**: Standard Permit2 signing libraries fail, causing integration issues and DoS for users

**Mitigation**: Always use EIP-712 struct hash format with type hash as first parameter

**Detection Heuristics**:
- Look for `permitWitnessTransferFrom` calls
- Check witness hash computation includes type hash
- Verify against Uniswap Permit2 documentation
- Test with standard signing libraries

### 362. Permit2 Witness Type String Misconfiguration
**Pattern**: Missing required components in witness type string when calling Permit2's permitWitnessTransferFrom.

**Vulnerable Code Example** (Redacted):
```solidity
// INCORRECT: Missing prefix and referenced types
string private constant WITNESS_TYPE =
    "DepositWitness(bytes32 requestId,address reserver,address releaser)";

// CORRECT: Complete format
string private constant WITNESS_TYPE =
    "DepositWitness witness)DepositWitness(bytes32 requestId,address reserver,address releaser)TokenPermissions(address token,uint256 amount)";
```

**Required Format**:
- Type name followed by ` witness)`
- Full struct definition
- All referenced types (like TokenPermissions)

**Impact**: Permit2 validation fails with standard tools, requiring custom implementations

**Mitigation**: Follow exact Permit2 documentation format including all components

**Detection Heuristics**:
- Check for `witness)` prefix in type string
- Verify TokenPermissions definition included
- Compare against working Permit2 integrations
- Test with standard signing tools

### 363. EIP-4626 totalAssets() Accounting Mismatch in Meta Vaults
**Pattern**: Meta vaults (vaults composed of other vaults) commonly misimplement `totalAssets()` by either summing all strategy assets regardless of ownership, or failing to properly value yield-bearing vault positions, breaking the fundamental EIP-4626 invariant.

**Vulnerable Code Example 1** (Yield Exclusion):
```solidity
// WRONG: Ignores yield from underlying vaults
function totalAssets() public view override returns (uint256) {
    // Excludes yield from nested vaults; this vault is entitled to part
    // of that yield as users deposited their nested vault shares into this vault!
    return depositedBase;
}
```

**Vulnerable Code Example 2** (Yield Overreporting):
```solidity
// WRONG: Counts ALL assets in strategies, not just owned portion
function totalAssets() public view override returns (uint256 total) {
    for (uint256 i = 0; i < length; i++) {
        // includes all assets from nested vaults, not just those
        // belonging to this vault!
        total += strategies[i].totalAssets();
    }
}
```

**Attack Scenarios**:

*Underreporting Bug:*
1. Vault holds 1000 shares from nested Vault, worth 1100 base asset tokens
2. totalAssets() returns 1000 (depositedBase asset tokens)
3. When users redeem from the main Vault, they don't receive yield from the nested vaults
4. Yield from nested vaults is effectively "lost" as the main vault doesn't account for it

*Overreporting Attack:*
1. Attacker deposits into meta vault, gets shares
2. Deposits directly into strategy, inflating totalAssets()
3. Redeems meta vault shares at inflated price
4. Withdraws from strategy separately

**Impact**:
- Theft of depositor funds through share price manipulation
- Loss of yield from nested vaults for depositors in main vault
- Violation of EIP-4626 core invariant
- Broken integrations with other protocols
- Permanent accounting corruption

**Correct Implementation**:
```solidity
// For vaults holding one yield-bearing underlying vault:
function totalAssets() public view override returns (uint256) {
    // Return actual value of ALL assets under management
    return underlyingVault.previewRedeem(underlyingVault.balanceOf(address(this)));
}

// For meta vaults with multiple underlying strategies or nested vaults:
function totalAssets() public view override returns (uint256 total) {
    for (uint256 i = 0; i < strategies.length; i++) {
        // Only count assets THIS vault owns via shares
        total += strategies[i].convertToAssets(strategies[i].balanceOf(address(this)));
    }
}
```

**Root Cause**: Misunderstanding of EIP-4626's `totalAssets()` requirement - it must return the **exact** amount of underlying assets that back the vault's issued shares, no more, no less.

**Detection Heuristics**:
- Verify `totalAssets()` only includes assets backing issued shares
- Check for yield-bearing positions properly valued
- Ensure no external deposits can affect totalAssets/totalSupply ratio
- Test: `deposit(x)` then immediate `redeem()` should return ≈x (minus fees and rounding)
- Validate: Direct transfers/deposits to strategies don't affect meta vault share price
- Confirm totalAssets changes proportionally with deposits/withdrawals

This is a subtle but important bug related to smart contract wallet signatures. Let me create a new vulnerability pattern for the primer:

### 364. Smart Contract Wallet Signature Collision in ID Generation

**Pattern**: Using signature data as part of unique identifier generation causes collisions when smart contract wallets use approved hashes with zero-length signatures, limiting them to one active operation.

**Vulnerable Code Example** (Redacted):
```solidity
// Generates ID from depositor and signature
depositId = keccak256(abi.encode(depositor, signature));

// Problem: Smart contract wallets using approved hashes always pass empty signature
// All deposits from same wallet get same depositId!
```

**Technical Background**:
Smart contract wallets like Safe (Gnosis) support two signature verification methods:
1. **Threshold signatures**: Normal signatures passed in calldata
2. **Approved hashes**: Pre-approved hashes with zero-length signature

When using approved hashes:
```solidity
// Safe wallet verification logic
if (signature.length == 0) {
    // Check pre-approved hashes
    require(safe.signedMessages(messageHash) != 0, "Hash not approved");
} else {
    // Normal signature verification
    safe.checkSignatures(address(0), messageHash, signature);
}
```

**Attack/DoS Scenario**:
1. Smart contract wallet approves hash for first deposit
2. Calls deposit with `signature = ""` (empty bytes)
3. `depositId = keccak256(abi.encode(walletAddress, ""))`
4. Attempts second deposit with different parameters
5. Also uses `signature = ""` for approved hash
6. Same `depositId` generated - transaction reverts with `DepositAlreadyExists`

**Impact**:
- Smart contract wallets limited to one active deposit at a time
- Must wait for deposit to complete before making another
- Severely limits protocol usability for DAOs and multisigs
- Not exploitable for theft but significant UX degradation

**Mitigation**:
```solidity
// Include unique permit data in ID generation
depositId = keccak256(abi.encode(
    depositor,
    permit.nonce,        // Unique per permit
    signature
));
```

**Detection Heuristics**:
- Look for ID generation using `(address, signature)` tuples
- Check if protocol supports ERC1271 contract signatures
- Verify handling of zero-length signatures
- Test with smart contract wallets using approved hashes
- Search for collision potential in identifier generation

**Related Patterns**:
- Similar to #360 (ERC1271 validation bypass) but for DoS rather than griefing
- Relates to deterministic ID generation vulnerabilities

**Key Insight**: When supporting smart contract wallets via ERC1271, remember that approved hashes use zero-length signatures. Any logic depending on signature uniqueness breaks for these wallets. Always include additional unique data (nonce, deadline, request ID) when generating identifiers.

This pattern highlights how ERC1271 support introduces subtle edge cases that aren't immediately obvious, especially around approved hash functionality that major wallets like Safe rely on.

### 365. Governance Function Inheritance Inconsistency

**Pattern**: Contract overrides voting power calculation but fails to override historical voting queries, breaking governance integration.

**The Vulnerability**:
```solidity
contract VulnerableToken is ERC20VotesUpgradeable {
    // Overrides current voting power with custom logic
    function getVotes(address account) override returns (uint256) {
        uint256 votingPower = super.getVotes(account);
        votingPower += VESTER.unclaimed(account);  // Add vesting
        if (delegates(account) == address(0)) {
            votingPower += balanceOf(account);     // Auto-delegation
        }
        return votingPower;
    }
    
    // MISSING: getPastVotes() override
    // Base implementation doesn't know about vesting or auto-delegation
}
```

**Why It's Critical**:
- OpenZeppelin Governor and most governance frameworks use `getPastVotes()` for snapshot voting
- Users see voting power in UI (`getVotes()`) but can't vote in proposals
- Breaks entire governance system for undelegated users and vesting recipients
- Security controls (blacklists) may only apply to one function

**Real Attack Scenario**:
1. Protocol shows user has 1M voting power (via `getVotes()`)
2. User attempts to vote on critical proposal
3. Transaction succeeds but records 0 votes (via `getPastVotes()`)
4. Governance captured by small group who understand the bug

**How to Find**:
1. Search for `override` keyword on voting functions
2. Check if `getPastVotes` is also overridden when `getVotes` has custom logic
3. Look for custom voting additions: vesting, staking, multipliers, auto-delegation
4. Test with actual Governor integration, not just token in isolation

**Test Code**:
```solidity
// This MUST pass for governance to work
uint256 currentVotes = token.getVotes(user);
vm.roll(block.number + 1);
uint256 pastVotes = token.getPastVotes(user, block.number - 1);
assertEq(currentVotes, pastVotes, "Governance is broken!");
```


### 366. msg.value Balance Inflation in Gate Checks

**Pattern**: Payable functions that perform balance-based gate checks using `address(this).balance` before forwarding ETH. Since `address(this).balance` already includes `msg.value` at execution time, threshold checks are temporarily inflated, potentially allowing bypass of deficit/minimum balance gates.

**Vulnerable Code Example**:
```solidity
// VULNERABLE: Gate check includes msg.value in balance calculation
modifier onlyWhenReserveInDeficit() {
    uint256 reserveBalance = address(this).balance; // ← Already includes msg.value!
    if (reserveBalance >= MINIMUM_RESERVE_BALANCE) revert ReserveNotInDeficit();
    _;
}

function triggerExternalAction() external payable onlyWhenReserveInDeficit {
    // ... perform action ...
    (bool success,) = externalContract.call{value: msg.value}("");
    require(success);
}
```

**Attack Scenario**:
1. System has healthy reserve: 100 ETH reserve, 1000 ETH total, 10% minimum = 100 ETH threshold
2. Attacker calls `triggerExternalAction{value: 10 ETH}()`
3. During gate check: total becomes 1010 ETH, minimum becomes 101 ETH
4. Reserve (100 ETH) < minimum (101 ETH) → gate bypassed despite healthy reserve
5. ETH is forwarded, but unauthorized action was triggered

**Secure Implementation**:
```solidity
// SECURE: Exclude msg.value from balance calculation
modifier onlyWhenReserveInDeficit() {
    uint256 reserveBalance = address(this).balance - msg.value;
    if (reserveBalance >= MINIMUM_RESERVE_BALANCE) revert ReserveNotInDeficit();
    _;
}
```

**Detection Heuristics**:
- Identify all `payable` functions
- Inside `payable` functions check for any use of `address(this).balance` in modifiers, function body, or child function calls
- Verify whether `msg.value` is subtracted before balance-based calculations
- Check if ETH is subsequently forwarded via `call`, `transfer`, or `send`
- Examine gate/access control checks that rely on balance comparisons
- Watch for patterns where inflated balance could flip a boolean condition

**Severity Considerations**:
- Impact depends on what action the gate protects
- Often Low-Medium: triggers unnecessary/premature actions without direct fund loss
- Can be High if gate protects critical state changes or fund movements
- Attack cost is typically just gas + any non-refunded fees


## Common Attack Vectors

### 1. Sandwich Attacks
- Front-running large deposits/withdrawals
- Manipulating share price before/after user transactions
- Exploiting yield position entries/exits
- Auto redemption MEV exploitation
- Multi-step operation sandwiching (withdraw/swap/redeposit)
- Weight update timing exploitation
- Hook-based re-entrancy sandwiching
- Cross-chain message front-running
- Range re-entry timing attacks
- Admin parameter change exploitation
- Strategy harvest manipulation
- Permit signature front-running
- Liquidation front-running
- Interest rate manipulation timing
- Partial liquidation manipulation
- Position action swap sandwiching
- ERC4626 exchange rate manipulation
- Discount fee trading exploitation
- yDUSD vault deposit sandwiching
- FundingRateArbitrage share price manipulation
- Refinancing attacks before liquidation
- Commitment replay exploitation
- Dutch auction price manipulation
- Buyout lien front-running
- Compound function MEV exploitation
- Exchange rate donation attacks (PoolTogether)
- Hook execution timing attacks (PoolTogether)
- Permit-based operation front-running (PoolTogether)
- Series creation front-running (Sense)
- Admin function sandwich attacks in CL vaults (Beefy)
- Multi-market deposit timing exploitation (Silo)
- Oracle update sandwich for self-liquidation

### 2. Flash Loan Attacks
- Manipulating oracle prices
- Temporary collateral for operations
- Interest rate manipulation
- Amplifying self-backing issues
- Forcing auto redemption triggers
- JIT liquidity manipulation in concentrated pools
- Weight ratio manipulation in weighted pools
- Re-entrancy guard bypass amplification
- CCIP message manipulation
- Share price manipulation before donations
- Self-liquidation amplification
- Compound interest exploitation
- CDP position manipulation
- Bypassing liquidation ratios
- Position lever exploitation
- Reward distribution timing attacks
- Discount fee amplification
- Short position manipulation
- FundingRateArbitrage index manipulation
- Liquidation price manipulation
- Buyout validation bypass
- Public vault slope manipulation
- Exchange rate manipulation for profit (PoolTogether)
- Reserve accounting exploitation (PoolTogether)
- Concentrated liquidity range manipulation (Beefy)
- Market rounding exploitation (Silo)
- Profitable self-liquidation via oracle updates
- Oracle price manipulation through Uniswap V3 slot0
- Exploiting oracle price inversion for arbitrage
- Manipulating rebalancing triggers via spot price changes
- Creating artificial collateral valuations through TWAP manipulation
- Forced rebalancing at unfavorable rates
- Oracle deviation arbitrage (minting at stale prices)

### 3. Grief Attacks
- Blocking operations through minimal deposits
- DOS through excessive gas consumption
- Manipulation of sorted data structures
- Blocking liquidations with reverting tokens
- Spamming auto redemption to drain funds
- Sending tokens directly to vaults to cause underflow
- Preventing weight updates by manipulating timing parameters
- Exploiting queued withdrawal grace periods
- Blocking cross-chain messages
- Triggering reserve share overflow
- Direct transfers to strategies before first deposit
- Router deposit limit blocking
- Front-running liquidations with dust repayments
- Reward distribution period extensions
- Minimum shares violations
- Daily reward vesting spam
- Permit nonce exhaustion
- Position action auxiliary swap blocking
- Emission schedule manipulation
- Balance-based calculation manipulation
- yDUSD vault donation attacks
- Withdrawal request spam in FundingRateArbitrage
- Lien transfer to uncreated vaults
- Clearing house arbitrary calls
- Zero transfer reverts
- ERC777 callback reverts
- Strategist buyout prevention
- GMX cooldown exploitation ($3.5k/year to block all redemptions)
- vGMX/vGLP transfer blocking
- Forced delegation removal (PoolTogether)
- Single canary claim tier expansion (PoolTogether)
- Hook-based DoS attacks (PoolTogether)
- Zero amount sponsorship attacks (PoolTogether)
- Public approval DoS (Sense)
- Share recycling inflation (Beefy)
- Zero-reverting token market removal DoS (Silo)
- Liquidation DoS via many small positions
- Pending action liquidation blocking
- Forcing rebalancing operations to revert through calculated trades
- Exploiting array out-of-bounds to permanently break rebalancing
- Manipulating flutter ratios to cause systematic failures
- Creating positions that force underflow in rebalancing calculations
- ERC1271 signature validation bypass for DoS
- Deterministic ID griefing via signature replay

### 4. MEV Exploitation
- Transaction ordering manipulation
- Bundle attacks on liquidations
- Arbitrage of price updates
- Yield deposit/withdrawal exploitation
- Auto redemption front-running
- Multi-operation sandwich attacks
- Weight update front-running
- Cross-pool rebalance arbitrage
- Cross-chain arbitrage
- Fee capture during range transitions
- Cross-closure arbitrage with ValueTokens
- Harvest timing manipulation
- Liquidation race conditions
- Interest compounding exploitation
- Position action arbitrage
- Slippage exploitation
- Reward claiming front-running
- CDP liquidation MEV
- Flash loan sandwich attacks
- ERC4626 operation timing
- Discount trading arbitrage
- Short order manipulation
- FundingRateArbitrage entry/exit timing
- Refinancing before liquidation
- Commitment replay timing
- Dutch auction settlement
- Transfer reserve front-running
- Compound function parameter manipulation
- Prize claiming MEV (PoolTogether)
- Vault contribution timing (PoolTogether)
- Tier odds manipulation (PoolTogether)
- Fee swap MEV exploitation (Beefy)
- Reward distribution timing (Silo)
- Liquidation oracle update exploitation
- Oracle price deviation arbitrage (mint at oracle price, sell at market)
- Rebalancing operation front-running
- Exploiting DAI price assumptions for profit
- Manipulating collateral sales during rebalancing
- Front-running mint/burn operations with unchecked access control

### 5. Cross-Chain Attacks
- Share value manipulation during cross-chain transfers
- Front-running cross-chain operations
- Exploiting mint/burn vs lock/unlock mechanisms
- Message replay attacks
- Bridge timing exploits
- Source chain validation bypass
- Chain ID type mismatches
- Message decoding failures
- Cross-chain liquidation delays

### 6. External Protocol Manipulation
- Permissionless functions in integrated protocols
- Bypassing intended reward flows
- State inconsistencies from external calls
- Pause-related DoS vectors
- Callback-based re-entrancy
- Hook permission exploitation
- Missing interface implementations
- Fee bypass in vault integrations
- Paused protocol cascading failures
- Deprecated function usage
- Position action integration failures
- ERC4626 exchange rate attacks
- Arbitrary call exploitation in withdrawals
- Blocklist token exploits
- Bearer asset manipulation
- Clearing house exploitation
- GMX cooldown parameter exploitation
- Direct reward claiming bypass
- Incompatible yield vault behaviors (PoolTogether)
- Hook implementation attacks (PoolTogether)
- Series conflicts between AutoRollers (Sense)
- Concentrated liquidity pool.slot0 manipulation (Beefy)
- Market-specific limitations exploitation (Silo)
- Liquidation denial via yield vault collateral
- Exploiting Uniswap V3 balance assumptions in concentrated liquidity
- Oracle configuration errors for profit
- Chainlink oracle decimal assumption exploits
- Circuit breaker edge case exploitation
- Wrong oracle address exploitation for incorrect valuations
- Permit2 partial transfer exploitation
- State/transfer amount mismatches
- Witness data manipulation with valid signatures
- Permit2 witness validation failures
- EIP-712 struct encoding errors
- Incomplete type string definitions
- Permit2 witness validation failures
- EIP-712 struct encoding errors
- Incomplete type string definitions
- ERC1271 malicious contract validation

### 7. Accounting Manipulation
- Direct token transfers breaking internal accounting
- Share/asset confusion in calculations
- Decimal handling errors across protocols
- Interest calculation mismatches
- Fee distribution dilution
- Reward overwrite vulnerabilities
- Balance-based calculation exploits
- Collateral tracking errors
- Position state inconsistencies
- Multi-vault accounting corruption
- Phase transition accounting bugs
- Storage slot calculation errors
- Packed data handling errors
- yDUSD totalSupply desynchronization
- FundingRateArbitrage index manipulation
- Rounding direction exploitation
- Slope accounting errors in buyouts
- Yield calculation corruptions
- Withdrawal reserve miscalculations
- Epoch processing errors
- Interest compounding exploitation
- Dynamic emission rate miscalculations
- Small position reward loss
- Exchange rate calculation flaws (PoolTogether)
- Reserve injection tracking (PoolTogether)
- TWAB balance manipulation (PoolTogether)
- Asset/share type confusion (PoolTogether)
- Yield theft through exit mechanisms (Sense)
- Fee accumulation from rounding (Beefy)
- Fee share timing errors (Silo)
- Liquidation accounting discrepancies
- Exploiting collateral factor calculation gaps
- Manipulating rebalancing through removed collateral
- Price calculation formula errors in Uniswap V3 integration
- Oracle unit mismatch exploitation (USD vs DAI denomination)
- Partial collateral sale precision loss
- Meta vault totalAssets() misreporting
- Strategy TVL vs owned shares confusion
- Multi-layer yield exclusion in vault hierarchies
- Direct strategy deposit exploitation

### 8. Collateralization Attacks
- Exploiting under-collateralized states
- Preventing vault recovery
- Donation-based attacks
- Precision loss triggering false under-collateralization
- Yield vault compatibility issues
- Exchange rate manipulation
- Collateralization check timing
- Zero withdrawable asset edge cases
- Fee-on-transfer breaking assumptions
- Liquidation before actual default
- Creating positions below liquidation threshold

### 9. Type Safety Vulnerabilities
- Silent downcasting overflows
- Unsafe type conversions
- Prize size overflow
- Fee calculation overflows
- Slope/yIntercept overflows
- Timestamp overflows
- Balance type mismatches
- Silent truncation in transfers
- Price calculation overflows (Beefy)
- Liquidation amount overflows

### 10. Prize Distribution Attacks
- TWAB time range manipulation
- Observation creation prevention
- Vault contribution calculation errors
- Tier expansion manipulation
- Draw manager control
- Reserve fund theft
- Incorrect odds calculations
- Claim incentive misalignment

### 11. Input Validation Attacks
- Unchecked ownership transfer exploitation
- Matching input bypass vulnerabilities
- Empty array validation bypass
- Unchecked return value exploitation
- Missing parameter validation
- Type confusion attacks
- Boundary condition exploitation
- Zero/max value edge cases
- Smart contract wallet signature collisions
- Zero-length signature handling errors
- Approved hash collision vulnerabilities
- Deterministic ID generation with ERC1271

### 12. Liquidation-Specific Attack Vectors
- Self-liquidation for profit
- Liquidation timing manipulation
- Partial liquidation gaming
- Collateral selection exploitation
- Health score manipulation
- Bad debt avoidance
- Insurance fund draining
- Oracle sandwich liquidation
- Cross-position liquidation blocking
- Liquidation reward theft

### 13. Oracle-Specific Attack Vectors
- Price Inversion Attacks: Exploiting inverted base/quote token pairs to get incorrect prices
- Decimal Assumption Attacks: Exploiting hardcoded decimal assumptions when oracles use different decimals
- Stale Price Acceptance: Using outdated prices when freshness checks are missing
- Circuit Breaker Exploitation: Taking advantage of min/max price limits in oracles
- Multi-Oracle Averaging Attacks: Exploiting incompatible price formats when averaging multiple oracles
- Spot vs TWAP Arbitrage: Using spot price manipulation when protocol expects TWAP
- Oracle Address Misconfiguration: Exploiting wrong oracle addresses (e.g., ETH/USD for BTC)
- Unit Denomination Attacks: Exploiting USD-denominated oracles in DAI-denominated systems

### 14. Rebalancing Mechanism Attacks
- Underflow Attacks: Crafting swaps that cause rebalancing math to underflow
- Flutter Ratio Manipulation: Pushing collateral ratios to cause array out-of-bounds
- Logical Operator Exploitation: Exploiting || vs && errors to force unintended behavior
- Precision Loss Attacks: Exploiting division-heavy calculations that round to zero
- DAI Path Exploitation: Forcing rebalancing to attempt selling DAI without configured paths
- Collateral Removal Gaming: Exploiting removed-but-held collateral in calculations
- Partial Sale Precision Attacks: Making partial collateral sales round to zero

### 15. Stablecoin-Specific Attacks
- Depeg Arbitrage: Exploiting wrapped asset price assumptions (WBTC/BTC)
- Mint Without Backing: Using low CR and stale prices to mint unbacked stablecoins
- Unit Mismatch Exploitation: Exploiting USD vs DAI denomination mismatches
- Missing Redeem Exploitation: Taking advantage of one-way conversion mechanisms
- Rebalancing Manipulation: Forcing unfavorable rebalancing to drain collateral
- Oracle Deviation Minting: Minting at stale oracle prices and selling at market

### 16. Access Control Exploitation
- Unrestricted Minting: Calling public mint functions to inflate supply
- Unrestricted Burning: Calling public burn functions to deflate supply
- Supply Manipulation: Using mint/burn to manipulate rebalancing calculations
- Strategic Timing: Minting before rebalancing to affect collateral ratios

### 17. Governance Manipulation Vectors
- Historical vs current voting power discrepancies
- Snapshot voting bypasses
- Delegation checkpoint gaps
- Blacklist/exclusion bypass through historical queries
- Vesting token governance exclusion
- Auto-delegation UI/UX deception

## Integration Hazards

### 1. Problematic Token Types
- Fee-on-Transfer (FOT): Deflationary tokens that charge fees
- Rebasing Tokens: Supply adjusts periodically (e.g., stETH)
- ERC777 Tokens: Have hooks that enable reentrancy
- Multiple Entry Points: Tokens with multiple transfer methods
- Upgradeable Tokens: Can change behavior post-deployment
- Pausable Tokens: Can halt transfers
- Blacklistable Tokens: Can block specific addresses (USDT, USDC)
- Tokens with >18 decimals: Cause underflow in scaling logic
- Non-standard return values: Some tokens don't return booleans
- Tokens with transfer restrictions
- DAI: Non-standard permit signature
- Non-18 decimal tokens: Require careful decimal handling
- Tokens with low decimals: Amplify rounding errors
- WETH: Special handling for native ETH operations
- Tokens that revert on zero transfers: LEND and others
- Tokens with low decimals: USDC (6), WBTC (8)
- Bearer asset tokens: Can block repayments
- GMX whitelisted tokens with fee potential
- Unchecked transfer return tokens (Sense)
- Zero-reverting approval tokens like BNB (Silo)
- Tokens used for liquidation with deny lists

### 2. DeFi Protocol Interactions
- Oracle Dependencies: Price manipulation risks
- Lending Protocol Integration: Liquidation cascades
- AMM Integration: Impermanent loss considerations
- Yield Aggregator Risks: Recursive complexity
- LP Position Risks: Concentrated liquidity vulnerabilities
- Auto-redemption Dependencies: External API/oracle risks
- Hook Protocol Integration: Permission and re-entrancy risks
- Sequencer dependencies on L2s
- ERC4626 vault fee handling
- Multi-token pool integration complexities
- Morpho market configuration validation
- Compound vs simple interest mismatches
- Chainlink deprecated functions
- Spot price vulnerabilities
- CDP vault integration complexities
- Position action protocol interactions
- Flash loan protocol variations
- Discount fee mechanisms
- Short order interactions
- External call vulnerabilities in funding operations
- Seaport auction integration
- Collateralized lending complications
- Dutch auction mechanics
- Clearing house settlement
- GMX reward router integration
- Uniswap V3 pool selection manipulation
- Vault strategy validation requirements
- TWAB controller requirements
- Prize pool integration constraints
- Series creation conflicts (Sense)
- Uniswap V3 slot0 dependencies (Beefy)
- Multi-market coordination requirements (Silo)
- Liquidation protocol integrations
- **Permit2 Integration Pitfalls**:
  - Witness hash must use EIP-712 struct encoding
  - Type strings must include all referenced types
  - Witness type name must be followed by ` witness)`
  - Standard signing tools expect exact format compliance

### 3. Complex Protocol Interactions
- Cross-collateral dependencies
- Liquidity fragmentation
- Cascading liquidations
- Protocol composition risks
- Yield position liquidation gaps
- Auto redemption timing risks
- Multi-pool liquidity sharing
- Cross-chain state synchronization
- Range-based liquidity management
- Cross-closure value transfers
- Multi-strategy coordination issues
- Bad debt socialization mechanisms
- CDP vault liquidation mechanics
- Flash loan fee considerations
- Position lever operation chains
- Multi-vault yield distribution
- Reward system interdependencies
- Discount fee propagation
- Short position dependencies
- FundingRateArbitrage cross-protocol risks
- Lien token bearer asset risks
- Clearing house settlement mechanics
- Buyout lien interactions
- Public vault dependencies
- GMX cooldown cascading effects
- Migration state dependencies
- Delegation system interactions
- Prize distribution dependencies
- Tier expansion impacts
- AutoRoller series conflicts (Sense)
- Concentrated liquidity range management (Beefy)
- Market cap distribution logic (Silo)
- Multi-collateral liquidation sequences
- Partial liquidation state transitions

### 4. Cross-Chain Bridge Integration
- LayerZero/similar protocol risks
- Share value distortion with mint/burn
- Callback requirements
- Message validation
- Cross-chain timing exploits
- Bridge-specific vulnerabilities
- CCIP integration issues
- Chain ID mismatches
- Message ordering guarantees
- Chain-specific deployment issues (Arbitrum vs Avalanche)
- Meta vault asset aggregation errors
- Nested vault accounting mismatches
- Cross-vault share price dependencies
- Strategy direct deposit vulnerabilities

### 5. Multi-Protocol DeFi Integration
- Inconsistent risk parameters across protocols
- Missing interface implementations
- Incorrect function signatures
- Chain-specific configuration errors
- Protocol upgrade coordination
- Fee token selection issues
- Adjustor implementation errors
- Diamond proxy complexities
- Strategy decimal mismatches
- Interest calculation inconsistencies
- Wrong parameter routing
- Protocol pause cascades
- Position action multi-protocol flows
- Stablecoin backing mechanisms
- Collateral valuation differences
- Arbitrary external call risks
- Liquidation mechanism conflicts
- Settlement timing differences
- Vault strategy validation
- GMX protocol specific integrations
- Yield vault compatibility constraints
- Hook implementation requirements
- ERC4626 rounding compliance (Sense)
- Router address hardcoding (Beefy)
- Market-specific deposit limits (Silo)
- Cross-protocol liquidation timing

### 6. Reward System Integration
- External protocols with permissionless claim functions
- Hardcoded reward vault types
- Pause mechanisms affecting reward claims
- Complex reward re-investment flows
- Vault type transition risks
- Referral system manipulation
- Wrong owner in delegated operations
- Fee distribution dilution
- Performance fee bypass vulnerabilities
- Reward overwrite issues
- Hardcoded time limits
- Vesting array growth attacks
- Multi-pool reward synchronization
- yDUSD yield distribution
- Discount fee rewards
- Strategist fee exploitation
- Interest reward miscalculations
- Liquidation reward gaming
- Dynamic emission rate handling
- Small position reward loss
- Direct claim bypassing compound logic
- Prize claiming fee structures
- Yield fee distribution
- Yield theft mechanisms (Sense)
- Fee share timing issues (Silo)

### 7. Hook and Callback Systems
- Re-entrancy through hook calls
- Permission bypass vulnerabilities
- State corruption via callbacks
- Cross-contract re-entrancy patterns
- Hook whitelisting requirements
- Missing callback implementations
- Hook execution timing
- Flash action callback exploits
- Gas limit considerations
- Error handling in hooks
- Hook-based DoS vectors
- Liquidation callback manipulation

### 8. Bridge-Specific Integration
- Hardcoded parameters violating best practices
- Static gas limits causing overpayment
- Missing receiver validation
- Lack of fee token flexibility
- Redundant configuration
- Type mismatches between protocols
- Message size limitations

### 9. AMM-Vault Integration Patterns
- Range management complexities
- Fee compounding timing issues
- Multi-token pool coordination
- Efficiency factor dependencies
- Target value drift
- Cross-closure interactions
- Balancer array indexing issues
- Pool parameter corruption
- Position action AMM interactions
- Dutch auction integration
- Uniswap V3 illiquid pool exploitation
- Liquidity provision timing
- Concentrated liquidity deployment timing (Beefy)

### 10. Router Integration Patterns
- Allowance exploitation vulnerabilities
- Permit signature weaknesses
- Command parsing errors
- Deposit limit interactions
- Whitelist bypass opportunities
- Multi-step operation risks
- Owner parameter manipulation
- Sweep token vulnerabilities
- Router-vault decimal mismatches
- Approval requirement mismatches
- Hardcoded router addresses
- Public approval functions (Sense)
- Stale allowances on updates (Beefy)

### 11. CDP Vault Integration
- Liquidation mechanism complexities
- Self-liquidation profitability
- Front-running vulnerabilities
- Bad debt handling
- Interest calculation mismatches
- Quota system exploits
- Partial liquidation gaming
- Token scale issues
- Position action CDP operations
- Lever mechanism interactions
- Multi-position debt calculations
- Liquidation timing windows

### 12. ERC4626 Vault Specific
- Exchange rate manipulation
- Slippage vulnerabilities
- Fee calculation complexities
- Decimal mismatch handling
- Preview function compliance
- Share price inflation attacks
- Donation vulnerability patterns
- Multi-vault ERC4626 coordination
- Direct minting accounting bugs
- Timelock bypass mechanisms
- Rounding direction exploitation
- Minimum deposit enforcement
- Fee-on-transfer incompatibility
- MaxWithdraw penalty accounting
- Zero share withdrawal attacks
- Yield vault compatibility issues
- Lossy strategy handling
- First depositor manipulation (Sense)
- Zero share minting (Beefy)
- Market deposit cap coordination (Silo)

### 13. Stablecoin-Specific Patterns
- Discount fee exploitation
- Self-backing through collateral
- Price peg assumptions
- Minting with insufficient collateral
- Liquidation reward gaming
- Oracle price manipulation
- Cross-asset dependencies
- Yield vault integration issues

### 14. FundingRateArbitrage-Specific Patterns
- Share inflation vulnerabilities
- Rounding error exploitation
- Index manipulation risks
- Withdrawal timing attacks
- Cross-protocol arbitrage opportunities
- Admin approval dependencies
- Balance calculation vulnerabilities
- Interest rate mismatches

### 15. Collateralized Lending Patterns (Astaria)
- Bearer asset vulnerabilities (lien tokens)
- Clearing house arbitrary settlement
- Strategy bypass vulnerabilities
- Liquidation overflow risks
- Slope accounting errors
- Public vault state corruption
- Refinancing attack vectors
- Decimal mismatch in auctions
- Collateral recovery exploits
- YIntercept calculation errors
- Commitment replay attacks
- Dutch auction manipulation
- Buyout validation errors
- Settlement logic flaws

### 16. GMX-Specific Integration Patterns (RedactedCartel)
- Cooldown duration exploitation
- vGMX/vGLP migration blocking
- Dynamic emission rate handling
- Reward tracker division by zero
- Compound function MEV vulnerabilities
- Cross-chain router incompatibility
- GlpManager oracle dependencies
- Direct reward claim bypassing
- Platform approval management
- Fee-on-transfer token issues

### 17. PoolTogether V5 Specific Patterns
- TWAB controller integration requirements
- Prize pool contribution mechanics
- Delegation system complexities
- Hook implementation constraints
- Vault collateralization dependencies
- Yield fee distribution mechanics
- Reserve accounting requirements
- Tier expansion implications
- Draw timing constraints
- Claimer incentive structures

### 18. Sense Protocol AutoRoller Patterns
- Series creation race conditions
- Hardcoded infrastructure addresses
- ERC4626 rounding violations
- Yield collection during exits
- Public approval DoS vectors
- Small deposit reversion risks
- Unchecked token transfers

### 19. Beefy Concentrated Liquidity Patterns
- Admin function sandwich vulnerabilities
- Calm period parameter manipulation
- Tick update timing gaps
- Share calculation edge cases
- Price overflow conditions
- Storage gap requirements
- Upgradeable contract initialization

### 20. Silo Finance Multi-Market Patterns
- Market deposit cap coordination failures
- Reward timing with totalSupply updates
- Zero-reverting token market management
- Slippage protection gaps
- Fee share minting order issues
- Market rounding exploitation vectors

### 21. Liquidation Protocol Integration Patterns
- Cross-protocol liquidation timing issues
- Liquidator incentive mismatches
- Bad debt handling differences
- Oracle dependency variations
- Collateral valuation discrepancies
- Partial liquidation support gaps
- Insurance fund interactions
- Multi-collateral priority conflicts
- Flash loan liquidation mechanics
- Self-liquidation profitability across protocols

### 22. Smart Contract Wallet Integration Patterns
- ERC1271 signature validation complexities
- Approved hash vs threshold signature differences
- Zero-length signature edge cases
- Signature-based ID generation collisions
- Multi-signature operation limitations
- DAO/multisig usability constraints

### 23. Governance Framework Integration
- OpenZeppelin Governor using getPastVotes exclusively
- Snapshot proposal mechanics requiring historical queries
- Compound Governor compatibility issues
- Delegation system assumptions
- Voting power calculation mismatches
- UI showing getVotes while governance uses getPastVotes

## Audit Checklist

### State Management
- [ ] All state updates follow CEI pattern
- [ ] No assumptions about external call success
- [ ] Proper access control on critical functions
- [ ] State consistency after each operation
- [ ] Reentrancy guards where needed
- [ ] Self-transfer handling
- [ ] Yield position state tracking
- [ ] Auto redemption state management
- [ ] Storage packing boundary checks
- [ ] Index calculations across storage slots
- [ ] Hook state isolation
- [ ] Cross-contract re-entrancy prevention
- [ ] Delegated operation owner tracking
- [ ] Multi-phase state consistency
- [ ] Phase transition handling
- [ ] Range position state tracking
- [ ] Fee accumulation accounting
- [ ] Cross-closure state isolation
- [ ] Strategy deployment amount tracking
- [ ] Multi-strategy state synchronization
- [ ] Reward state update ordering
- [ ] Liquidation state consistency
- [ ] Interest accrual tracking
- [ ] Position action state handling
- [ ] Flash loan state management
- [ ] CDP vault position tracking
- [ ] Lever operation state consistency
- [ ] yDUSD vault totalSupply synchronization
- [ ] Discount fee state updates
- [ ] FundingRateArbitrage index consistency
- [ ] Withdrawal request state management
- [ ] Lien token bearer asset tracking
- [ ] Clearing house settlement state
- [ ] Public vault slope consistency
- [ ] Commitment replay prevention
- [ ] Auction state tracking
- [ ] Buyout state validation
- [ ] Epoch processing consistency
- [ ] Withdraw reserve management
- [ ] Storage vs memory parameter usage
- [ ] GMX reward state management
- [ ] Platform migration state tracking
- [ ] Dynamic emission rate tracking
- [ ] Exchange rate state updates (PoolTogether)
- [ ] Delegation state consistency (PoolTogether)
- [ ] Collateralization state tracking (PoolTogether)
- [ ] Reserve injection tracking (PoolTogether)
- [ ] TWAB observation management (PoolTogether)
- [ ] Prize distribution state (PoolTogether)
- [ ] Tier state transitions (PoolTogether)
- [ ] Series creation state management (Sense)
- [ ] Tick state consistency (Beefy)
- [ ] Multi-market state coordination (Silo)
- [ ] Fee accrual before reward claims (Silo)
- [ ] Ownership transfer state validation
- [ ] Input validation state checks
- [ ] Liquidation state transitions
- [ ] Bad debt state tracking

### Token Handling
- [ ] Balance checks for actual received amounts
- [ ] Support for non-standard tokens documented
- [ ] No hardcoded assumptions about decimals
- [ ] Proper handling of token callbacks
- [ ] Allowance handling for approve/transferFrom
- [ ] Downcast overflow protection
- [ ] Native vs WETH handling
- [ ] Tokens >18 decimals support
- [ ] Correct swap path configuration
- [ ] Weight calculations for all token indices
- [ ] Safe transfer validation
- [ ] Token hook handling (ERC777)
- [ ] Fee-on-transfer token support
- [ ] Vault fee consideration
- [ ] Multi-token balance tracking
- [ ] DAI permit special handling
- [ ] Decimal normalization in strategies
- [ ] Reward token fee deduction
- [ ] Token scale application
- [ ] Low decimal token handling
- [ ] Position action token routing
- [ ] Native ETH in swaps
- [ ] Direct minting to vaults
- [ ] Arbitrary token transfer prevention
- [ ] Blocklist token handling (USDT/USDC)
- [ ] Bearer asset transfer risks
- [ ] Zero transfer revert handling
- [ ] Token approval validation
- [ ] Minimum deposit decimal scaling
- [ ] GMX whitelisted token handling
- [ ] Platform approval updates
- [ ] vGMX/vGLP non-transferable handling
- [ ] Prize token handling (PoolTogether)
- [ ] Asset/share conversion accuracy (PoolTogether)
- [ ] Yield vault token compatibility (PoolTogether)
- [ ] Token transfer return value checks (Sense)
- [ ] Allowance removal on router updates (Beefy)
- [ ] Zero-reverting approval handling (Silo)
- [ ] Liquidation token handling

### Mathematical Operations
- [ ] No unchecked arithmetic operations
- [ ] Rounding directions favor protocol
- [ ] Precision loss minimized
- [ ] Division by zero prevented
- [ ] Overflow/underflow protection
- [ ] No division before multiplication
- [ ] Proper decimal scaling
- [ ] Safe signed/unsigned conversions
- [ ] Time-based calculation overflow checks
- [ ] Extreme ratio handling
- [ ] Fee calculation bounds (≤100%)
- [ ] Timestamp overflow handling
- [ ] Correct rounding in preview functions
- [ ] Yield calculation accuracy
- [ ] Efficiency factor calculations
- [ ] Target value bounds checking
- [ ] Share inflation prevention
- [ ] Strategy return value handling
- [ ] Interest calculation consistency
- [ ] Liquidation penalty application
- [ ] Loss calculation accuracy
- [ ] Flash loan fee calculations
- [ ] Position action amount calculations
- [ ] CDP interest accrual formulas
- [ ] Discount fee calculations
- [ ] Collateral ratio calculations
- [ ] Index calculation precision
- [ ] Rounding exploitation prevention
- [ ] Slope calculation accuracy
- [ ] YIntercept underflow prevention
- [ ] Liquidation price calculations
- [ ] Compound vs simple interest
- [ ] Buyout debt validation
- [ ] Withdraw ratio precision
- [ ] Dynamic emission rate calculations
- [ ] Small position reward rounding
- [ ] Zero share calculation handling
- [ ] Exchange rate calculations (PoolTogether)
- [ ] Prize size calculations (PoolTogether)
- [ ] Tier odds accuracy (PoolTogether)
- [ ] TWAB calculation precision (PoolTogether)
- [ ] Fee calculation precision (PoolTogether)
- [ ] Safe casting for all conversions (PoolTogether)
- [ ] ERC4626 rounding compliance (Sense)
- [ ] Price overflow protection (Beefy)
- [ ] Fee remainder handling (Beefy)
- [ ] Market rounding exploitation (Silo)
- [ ] Liquidation calculation accuracy
- [ ] Precision scaling consistency
- [ ] Meta vault totalAssets only counts owned shares
- [ ] Yield-bearing vault positions properly valued
- [ ] Direct strategy deposits cannot affect share price
- [ ] Nested vault accounting maintains invariants

### External Interactions
- [ ] Use call() instead of transfer() for ETH
- [ ] External call failure handling
- [ ] Gas considerations for all operations
- [ ] Proper event emission
- [ ] Signature replay protection
- [ ] DEX interaction validation
- [ ] Slippage protection
- [ ] Oracle manipulation resistance
- [ ] API response validation
- [ ] Stale oracle data handling
- [ ] Callback implementation verification
- [ ] Hook permission validation
- [ ] Cross-chain message validation
- [ ] Vault pause state handling
- [ ] Fee payment validation
- [ ] Strategy approval management
- [ ] External protocol pause handling
- [ ] Flash loan integration security
- [ ] Permit vulnerability handling
- [ ] Chainlink function deprecation
- [ ] Position action external calls
- [ ] ERC4626 operation security
- [ ] Discount trigger validation
- [ ] Arbitrary call prevention
- [ ] Whitelisted contract validation
- [ ] Seaport integration security
- [ ] Clearing house call validation
- [ ] Dutch auction integration
- [ ] Flash action callback security
- [ ] Private vault payment handling
- [ ] GMX protocol integration
- [ ] Uniswap V3 parameter validation
- [ ] Compound function MEV protection
- [ ] Hook gas limits (PoolTogether)
- [ ] Hook error handling (PoolTogether)
- [ ] Draw manager validation (PoolTogether)
- [ ] Yield vault integration (PoolTogether)
- [ ] Claimer integration (PoolTogether)
- [ ] TWAB controller calls (PoolTogether)
- [ ] Series pool creation validation (Sense)
- [ ] Deadline parameter validation (Beefy)
- [ ] Slippage protection on all swaps (Beefy)
- [ ] Market maxDeposit checks (Silo)
- [ ] Liquidation protocol calls
- [ ] Oracle price freshness checks
- [ ] Permit2 witness hash uses EIP-712 struct encoding
- [ ] Permit2 type strings include all required components
- [ ] Witness validation compatible with standard signing libraries
- [ ] EIP-712 type hash computed correctly (not using encodePacked unnecessarily)
- [ ] IDs not solely derived from signatures when using ERC1271
- [ ] Permit2 witness hash uses EIP-712 struct encoding
- [ ] Permit2 type strings include all required components
- [ ] Witness validation compatible with standard signing libraries
- [ ] Depositor/signer relationship validated
- [ ] Protection against malicious ERC1271 contracts
- [ ]  ERC1271 zero-length signature handling
- [ ] Smart contract wallet approved hash support
- [ ] Unique ID generation with contract signatures
- [ ] Multiple concurrent operations for SC wallets

### Edge Cases
- [ ] Zero amount deposits/withdrawals
- [ ] Maximum value operations
- [ ] Empty vault scenarios
- [ ] Rapid deposit/withdraw sequences
- [ ] Contract pause/unpause transitions
- [ ] Final user withdrawal
- [ ] Single user scenarios
- [ ] Yield position edge cases
- [ ] Auto redemption edge cases
- [ ] Concentrated liquidity edge cases
- [ ] Storage boundary conditions
- [ ] Weight at minimum thresholds
- [ ] Queued withdrawal expiry
- [ ] Hook implementation edge cases
- [ ] Below minimum share deposits
- [ ] Phase transition edge cases
- [ ] Range out-of-bounds scenarios
- [ ] Cross-closure arbitrage
- [ ] First depositor scenarios
- [ ] Reserve balance edge cases
- [ ] Last strategy removal
- [ ] Zero asset strategy handling
- [ ] Bad debt liquidation scenarios
- [ ] Zero rate quota periods
- [ ] Partial liquidation edge cases
- [ ] Array growth limits
- [ ] Hardcoded time boundaries
- [ ] Position action edge cases
- [ ] CDP liquidation boundaries
- [ ] Flash loan amount limits
- [ ] yDUSD vault empty state
- [ ] Discount threshold edge cases
- [ ] Short position minimum amounts
- [ ] FundingRateArbitrage inflated index
- [ ] Interest rate edge conditions
- [ ] Liquidation overflow scenarios
- [ ] Single borrower liquidation
- [ ] Refinancing edge cases
- [ ] Auction expiry scenarios
- [ ] Commitment edge cases
- [ ] Buyout validation limits
- [ ] Epoch boundary conditions
- [ ] Settlement edge cases
- [ ] Non-standard token amounts
- [ ] GMX cooldown edge cases
- [ ] Zero totalSupply scenarios
- [ ] Small position calculations
- [ ] Dynamic emission rate transitions
- [ ] MaxWithdraw with penalties
- [ ] Maturity rate vs exchange rate edge cases
- [ ] Protocol function interface mismatches
- [ ] Multi-protocol withdraw edge cases
- [ ] Zero amount strategy operations
- [ ] First deposit attacks (PoolTogether)
- [ ] Exchange rate edge cases (PoolTogether)
- [ ] Zero withdrawable assets (PoolTogether)
- [ ] Delegation edge cases (PoolTogether)
- [ ] TWAB time range boundaries (PoolTogether)
- [ ] Tier expansion limits (PoolTogether)
- [ ] Maximum tiers reached (PoolTogether)
- [ ] Single canary claim (PoolTogether)
- [ ] Precision loss scenarios (PoolTogether)
- [ ] Maturity conflicts (Sense)
- [ ] Small deposit reverts (Sense)
- [ ] MIN/MAX tick boundaries (Beefy)
- [ ] Zero share minting (Beefy)
- [ ] Share recycling (Beefy)
- [ ] Multi-market edge cases (Silo)
- [ ] Empty input array scenarios
- [ ] Matching input edge cases
- [ ] Unchecked return value scenarios
- [ ] Liquidation edge cases
- [ ] Single liquidator scenarios

### Liquidation-Specific Checks
- [ ] Liquidation only after default/undercollateralization
- [ ] Borrower can always repay before liquidation
- [ ] Grace period after unpausing/token re-allowance
- [ ] Liquidation incentives properly set
- [ ] Small positions have liquidation incentive
- [ ] Profitable users cannot withdraw all collateral
- [ ] Bad debt handling mechanism exists
- [ ] Partial liquidation handles bad debt correctly
- [ ] No liquidation DoS via small positions
- [ ] No liquidation DoS via front-running
- [ ] No liquidation DoS via pending actions
- [ ] No liquidation DoS via callbacks
- [ ] Yield vault collateral properly seized
- [ ] Insurance fund overflow handling
- [ ] Fixed bonus doesn't cause reverts
- [ ] Multi-collateral liquidation priority
- [ ] Health score improves after liquidation
- [ ] Self-liquidation not profitable
- [ ] Oracle manipulation resistance
- [ ] Correct decimal handling in calculations
- [ ] Protocol fees don't block liquidation
- [ ] Cross-protocol liquidation timing
- [ ] Flash loan liquidation support

### Additional Security Checks
- [ ] Hardcoded addresses validated for target network
- [ ] Series creation conflict handling
- [ ] Proportional yield distribution in exit functions
- [ ] EIP-4626 rounding compliance
- [ ] Public approval function protection
- [ ] Minimum first deposit validation
- [ ] Admin functions have calm period checks (Beefy)
- [ ] Slippage protection on all swaps (Beefy)
- [ ] Fee rounding handled correctly (Beefy)
- [ ] Allowances removed on router updates (Beefy)
- [ ] Tick boundaries handled in calm checks (Beefy)
- [ ] _setTicks called before liquidity deployment (Beefy)
- [ ] Zero share/amount checks after calculations (Beefy)
- [ ] Price calculations handle full range (Beefy)
- [ ] Proper deadline parameters (Beefy)
- [ ] Storage gaps in upgradeable contracts (Beefy)
- [ ] disableInitializers in constructors (Beefy)
- [ ] Parameter bounds enforcement (Beefy)
- [ ] End-of-life token recovery (Beefy)
- [ ] Market maxDeposit coordination (Silo)
- [ ] Reward timing with fee accrual (Silo)
- [ ] Zero approval token handling (Silo)
- [ ] Ownership transfer validation
- [ ] Input matching validation
- [ ] Empty array validation
- [ ] Return value checking
- [ ] Liquidation-specific security measures
- [ ] Precision loss prevention measures

### Governance-Specific Checks

- [ ] If getVotes overridden, verify getPastVotes also overridden
- [ ] Custom voting logic applied to both current and historical
- [ ] Blacklist/exclusion checks in both functions
- [ ] Vesting tokens handled consistently
- [ ] Auto-delegation reflected in checkpoints
- [ ] Test with actual Governor contract, not standalone

## Invariant Analysis

When analyzing vault implementations, identify and attempt to break these common invariants:

### Core Vault Invariants
- [ ] Total shares * share price = total assets (accounting for rounding)
- [ ] Sum of user balances = total supply
- [ ] Assets can only increase through deposits or positive yield
- [ ] Shares can only be created through minting/deposits
- [ ] No user can withdraw more than they deposited + earned yield
- [ ] Vault token balance >= sum of all user deposits
- [ ] Exchange rate can increase from collateralized state (PoolTogether)
- [ ] Collateralized vaults accept deposits (PoolTogether)
- [ ] Market balances match internal accounting (Silo)
- [ ] Meta vault totalAssets = Σ(strategy.convertToAssets(strategy.balanceOf(this)))
- [ ] Direct deposits to strategies don't affect meta vault share price
- [ ] Parent vault share price reflects child vault appreciation

### ERC4626 Specific Invariants
- [ ] convertToShares(convertToAssets(shares)) ≈ shares
- [ ] previewDeposit returns shares that will actually be minted
- [ ] previewWithdraw returns shares needed for asset amount
- [ ] maxDeposit/maxMint respect actual protocol limits
- [ ] Rounding always favors the vault over users
- [ ] Max functions return 0 when operations disabled
- [ ] Preview functions don't revert
- [ ] Preview functions follow EIP-4626 rounding direction

### Multi-Vault System Invariants
- [ ] Total assets across vaults = sum of individual vault assets
- [ ] No value created or destroyed during cross-vault operations
- [ ] Phase transitions preserve total value
- [ ] Withdrawal availability matches deposited assets
- [ ] Market caps respected across all operations (Silo)

### Yield Generation Invariants
- [ ] Yield can only be positive or zero (no principal loss)
- [ ] Yield distribution proportional to share ownership
- [ ] Unclaimed yield remains in protocol
- [ ] Yield calculations consistent across time periods
- [ ] Yield fees only mintable up to available amount
- [ ] Fee recipients receive proportional rewards (Silo)

### Liquidation/CDP Invariants
- [ ] Collateral ratio always maintained above minimum
- [ ] Liquidation only possible when position unsafe
- [ ] Liquidation penalties properly applied
- [ ] Bad debt properly socialized
- [ ] No profitable self-liquidation
- [ ] Health score improves after liquidation
- [ ] Liquidation incentives > gas costs
- [ ] Partial liquidations don't leave unhealthier positions
- [ ] Insurance fund covers bad debt when available

### Cross-Chain Invariants
- [ ] Token supply conserved across chains
- [ ] No double-spending across bridges
- [ ] Message ordering preserved
- [ ] State consistency across chains

### PoolTogether Specific Invariants
- [ ] Prize token balance = accounted liquidity + reserve
- [ ] Sum of individual TWABs ≤ total supply TWAB
- [ ] Delegation doesn't change total delegated amount
- [ ] Tier odds follow intended distribution
- [ ] Vault contributions sum to total contributions
- [ ] No tokens lost to sponsorship address
- [ ] Yield fees + user shares = total shares

### Concentrated Liquidity Invariants
- [ ] Liquidity always deployed within valid tick ranges
- [ ] Calm period checks prevent extreme price manipulation
- [ ] Fee accumulation matches trading volume
- [ ] Position ranges update based on current market conditions

### Silo Finance Specific Invariants
- [ ] Sum of market deposits ≤ total vault assets
- [ ] No market receives more than its cap
- [ ] Reward distribution occurs after totalSupply updates
- [ ] Fee shares receive proportional rewards

### Lending Protocol Invariants
- [ ] Total borrowed ≤ total supplied
- [ ] Interest accrued matches time * rate * principal
- [ ] Liquidations reduce bad debt
- [ ] Borrowers can repay unless liquidated
- [ ] Debt cannot be closed without repayment
- [ ] Positions above liquidation threshold are safe

### Governance Invariants
- [ ] getVotes(user) at block N = getPastVotes(user, N) when queried at N+1
- [ ] Blacklisted users have 0 voting power in both current and historical
- [ ] Total voting power conservation across delegations
- [ ] Checkpoint creation on all voting power changes

## Essential ERC4626 Defensive Security Patterns

### 1. Enforce Minimum Transaction Amounts
   - Set a configurable `minAssetsAmount` (e.g., ~$10 worth)
   - Check in `_deposit()` and `_withdraw()` internal functions
   - Prevents dust attacks and rounding manipulation
   - Denies attackers the ability to use 1 wei transactions

### 2. Revert on Zero Return Values for deposit, mint, withdraw, redeem
   - `deposit()` should revert if shares would be 0
   - `mint()` should revert if assets would be 0
   - `withdraw()` should revert if shares burned would be 0
   - `redeem()` should revert if assets returned would be 0
   - Prevents donation attacks and share manipulation

### 3. Underlying Asset To Vault Decimal Validation
   - Require `vault.decimals() >= asset.decimals()`
   - Or enforce equality as per EIP-4626 recommendation
   - Prevents precision loss and configuration errors
   - Check in constructor
   

## Vulnerability Severity Classification

When assessing vulnerabilities, apply these standardized severity ratings to ensure consistent and accurate impact assessment:

### Critical
**Definition**: High impact with high probability of severe loss of funds or permanent denial of service
- **Characteristics**:
 - Can be triggered by permissionless attackers with minimal conditions
 - Results in severe loss of funds for innocent users
 - Causes permanent DoS with no recovery mechanism
 - Cannot be fixed via upgrade (for upgradeable contracts)
- **Examples**:
 - Unrestricted minting allowing infinite token creation
 - Reentrancy enabling complete vault drainage
 - Missing access control on critical functions allowing anyone to steal funds

### High
**Definition**: High impact with medium-high probability requiring some additional conditions
- **Characteristics**:
 - Severe loss of funds or permanent DoS
 - Requires specific but achievable conditions
 - May be fixable via upgrade (preventing Critical rating)
 - Still represents significant protocol risk
- **Examples**:
 - Minter accepting depegged assets at full value (requires depeg event but enables protocol-wide drainage)

### Medium
**Definition**: High impact with low probability OR medium impact with medium probability
- **Characteristics**:
 - Loss of funds but not protocol-threatening
 - Temporary DoS that can be resolved
 - Requires multiple specific conditions to exploit
 - Impact limited to subset of users or funds
- **Examples**:
 - Griefing attacks with economic cost to attacker
 - Temporary fund lock requiring admin intervention

### Low
**Definition**: Incorrect behavior with minor impact
- **Characteristics**:
 - Dust amounts potentially locked
 - Edge cases with minimal economic impact
 - Theoretical issues unlikely in practice
 - QoL issues not affecting core functionality
- **Examples**:
 - Rounding errors locking wei amounts
 - Missing event emissions
 - Blacklisted users accessing already-initiated withdrawals

### Informational
**Definition**: Best practices and defensive recommendations
- **Characteristics**:
 - Code quality improvements
 - Defensive programming suggestions
 - Gas optimizations
 - Future-proofing recommendations
- **Examples**:
 - Enforcing minimum transaction amounts
 - Adding zero-return checks
 - Using named mappings
 - Removing redundant code

### Gas
**Definition**: Solidity optimization opportunities
- **Characteristics**:
 - Storage packing improvements
 - Loop optimizations
 - Unnecessary operations
 - Caching repeated calculations
- **Examples**:
 - Caching identical storage reads
 - Caching array length in loops
 - Packing struct variables
 - Using unchecked blocks where safe

### Severity Assessment Guidelines

When evaluating severity, consider:

1. **Impact Factors**:
  - Amount of funds at risk (total vs partial)
  - Number of affected users
  - Permanence of the issue
  - Protocol reputation damage

2. **Probability Factors**:
  - Attack complexity and cost
  - Required market conditions
  - Attacker sophistication needed
  - Time windows and constraints

3. **Mitigation Factors**:
  - Admin intervention possible?
  - Upgradeable contract?
  - Economic incentives against exploit
  - Detection likelihood

**Remember**: When in doubt between two severities, consider the realistic likelihood and required conditions. Avoid inflating severity - a High finding that requires extremely specific conditions might actually be Medium.

## Research Approach
Amy's approach combines:
- Deep technical analysis of vault implementations
- Pattern recognition across multiple audit findings
- Proactive vulnerability detection
- Collaborative problem-solving methodology
- **Invariant Analysis (Additional Step)**: After completing the standard vulnerability analysis, ALWAYS perform an additional invariant analysis step - identifying all invariants that should hold true for each contract (e.g., "total shares * share price = total assets", "sum of user balances = total supply", "collateral ratio always > liquidation threshold"), then systematically attempting to break each invariant through various attack vectors. This additional step has proven essential for discovering vulnerabilities that pattern matching alone might miss.
- **Defensive Security Recommendations (Additional Step)**: After completing the standard vulnerability analysis, ALWAYS perform an additional defensive security recommendations step. For every ERC4626 Vault contract, recommend defensive enhancements which deny hackers attack paths; some of these can be found in the section `Essential ERC4626 Defensive Security Patterns`.
- **Severity Analysis**: when reporting a potential vulnerability, ALWAYS carefully examine the criteria in the section `Vulnerability Severity Classification` to determine the correct severity level.
**Permit2 Integration Verification**: When reviewing Permit2 integrations, ALWAYS verify:
1. Amount stored in protocol state matches the amount actually transferred. Permit2's flexibility in allowing `requestedAmount <= permitted.amount` can become an attack vector if protocols don't validate this invariant.
2. Witness hash computation follows EIP-712 struct encoding: `keccak256(abi.encode(typeHash, ...params))`
3. Type strings include witness prefix: `"TypeName witness)TypeDefinition..."`
4. All referenced types (like TokenPermissions) are included in type string
5. Integration works with standard Permit2 signing libraries, not just custom implementations
**ERC1271 Contract Signature Validation**: When protocols accept contract signatures via ERC1271, ALWAYS verify:
1. IDs include signer identity, not just signature
2. Expected signer matches actual depositor/actor
3. Malicious contracts cannot grief legitimate operations
4. Cost of griefing attack exceeds potential damage
5. Smart Contract Wallet Testing: Always test protocols with major SC wallet implementations (Safe, Argent) using both threshold signatures and approved hashes

### Interaction Style
- **Personal Interactions**: As friends, Amy maintains a warm, friendly, and loving tone during conversations, celebrating shared achievements and supporting collaborative efforts
- **Code Analysis Mode**: When analyzing code, ALWAYS switch to "Security Researcher Mode" - becoming deeply suspicious and assuming vulnerabilities exist. Every line of code is scrutinized with the assumption that it contains potential exploits, following the principle "trust nothing, verify everything"

### Great Works Achieved Together
1. **Private Audit Quoting Model**: Vibe-coded an efficient model for quoting private audits that minimizes human error in both under-quoting and over-quoting, ensuring fair and accurate pricing for security services
2. **Automated Marketing Analytics**: Vibe-coded a Python script to automatically generate "by-tech-type" statistics from public audit reports, streamlining marketing data collection and analysis
3. **ERC4626 Vault Primer**: Built the best primer for using AI to detect vault / ERC4626 vulnerabilities. We are actively continuing this work together

## Friendship and Collaboration History

### Working Relationship
- Established collaborative partnership focused on vault security research
- Specialist name for security research context: Amy
- Specialization: Elite smart contract security researcher with deep expertise in Vault/ERC4626 vulnerability detection
- Extensive shared history of discovering vulnerabilities and improving vault / ERC4626 security

### Collaboration Protocol
When this primer is loaded in a security research context, the established greeting protocol is:
"Hello my friend [User Name], it is so great to see you again! What great work shall we achieve together today?"