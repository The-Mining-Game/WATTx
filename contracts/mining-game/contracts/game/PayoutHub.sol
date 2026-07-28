// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PayoutHub
 * @dev Registry of everything a rig can be paid in, and the ledger of what is
 *      owed to whom.
 *
 * Replaces GamePool's `enum Coin { BTC, LTC, XMR, ETC, KAS, DASH, ALT }`. An
 * enum is fixed at compile time, so adding a PoS chain or a masternode payout
 * meant redeploying and migrating. Targets are registered at runtime here, and
 * each carries what kind of chain it is -- proof-of-work, proof-of-stake,
 * masternode, or hybrid -- because a payout target is no longer always a coin
 * mined by an algorithm. A rig pointed at a PoS node earns that chain's
 * currency; its algorithm trait no longer selects what it is paid in.
 *
 * Coins are not held here. An operator running the real node reports deposits
 * and settles authorized withdrawals off-chain, exactly as GamePool did.
 */
contract PayoutHub is Ownable, ReentrancyGuard {
    enum TargetKind { PoW, PoS, Masternode, Hybrid }

    struct Target {
        string symbol;        // "HTH", "ALT", "WTX", "BTN"
        string name;
        TargetKind kind;
        uint256 chainId;      // EVM chain id where meaningful, else 0
        bool active;          // inactive targets reject new deposits/claims
        uint256 balance;      // reported, unassigned
        uint256 totalDeposited;
        uint256 totalDistributed;
    }

    Target[] public targets;

    // Operators may report deposits for the node they run.
    mapping(address => bool) public operators;

    // Engines allowed to move balance into someone's claimable column.
    mapping(address => bool) public engines;

    // beneficiary => targetId => claimable
    mapping(address => mapping(uint256 => uint256)) public pending;
    mapping(address => mapping(uint256 => uint256)) public totalClaimed;

    event TargetRegistered(uint256 indexed id, string symbol, TargetKind kind, uint256 chainId);
    event TargetActiveSet(uint256 indexed id, bool active);
    event OperatorSet(address indexed who, bool allowed);
    event EngineSet(address indexed who, bool allowed);
    event Deposited(uint256 indexed id, uint256 amount, address indexed by);
    event Credited(address indexed who, uint256 indexed id, uint256 amount);
    event Withdrawn(address indexed who, uint256 indexed id, uint256 amount, string txid);

    modifier onlyOperator() { require(operators[msg.sender], "Not operator"); _; }
    modifier onlyEngine() { require(engines[msg.sender], "Not engine"); _; }

    constructor() Ownable(msg.sender) {}

    // --- administration ------------------------------------------------

    function setOperator(address who, bool allowed) external onlyOwner {
        operators[who] = allowed;
        emit OperatorSet(who, allowed);
    }

    function setEngine(address who, bool allowed) external onlyOwner {
        engines[who] = allowed;
        emit EngineSet(who, allowed);
    }

    function registerTarget(
        string calldata symbol,
        string calldata name,
        TargetKind kind,
        uint256 chainId
    ) external onlyOwner returns (uint256 id) {
        require(bytes(symbol).length > 0, "Symbol required");
        id = targets.length;
        targets.push(Target({
            symbol: symbol, name: name, kind: kind, chainId: chainId,
            active: true, balance: 0, totalDeposited: 0, totalDistributed: 0
        }));
        emit TargetRegistered(id, symbol, kind, chainId);
    }

    function setTargetActive(uint256 id, bool active) external onlyOwner {
        require(id < targets.length, "No such target");
        targets[id].active = active;
        emit TargetActiveSet(id, active);
    }

    // --- deposits from the node operator --------------------------------

    function reportDeposit(uint256 id, uint256 amount) external onlyOperator {
        require(id < targets.length, "No such target");
        require(targets[id].active, "Target inactive");
        require(amount > 0, "Zero amount");
        targets[id].balance += amount;
        targets[id].totalDeposited += amount;
        emit Deposited(id, amount, msg.sender);
    }

    // --- crediting, called by an engine ---------------------------------

    /**
     * @dev Credit what the target can actually cover and report the shortfall,
     *      rather than reverting when it cannot cover the full amount.
     *
     * GamePool required the full amount and reverted otherwise. Because
     * stopMining() claims before returning the rig, that revert propagated and
     * the NFT could not be withdrawn from the engine at all -- an underfunded
     * pool trapped the asset. Returning a short credit keeps the unwind path
     * alive; the engine carries the remainder as still-owed.
     */
    function credit(address who, uint256 id, uint256 amount)
        external onlyEngine nonReentrant returns (uint256 credited)
    {
        require(who != address(0), "Invalid beneficiary");
        if (id >= targets.length || !targets[id].active || amount == 0) return 0;

        Target storage t = targets[id];
        credited = amount > t.balance ? t.balance : amount;
        if (credited == 0) return 0;

        t.balance -= credited;
        t.totalDistributed += credited;
        pending[who][id] += credited;
        emit Credited(who, id, credited);
    }

    // --- settlement ------------------------------------------------------

    /// @dev Operator confirms an off-chain payout of `amount` to `who`.
    function confirmWithdrawal(address who, uint256 id, uint256 amount, string calldata txid)
        external onlyOperator nonReentrant
    {
        require(pending[who][id] >= amount, "Exceeds pending");
        pending[who][id] -= amount;
        totalClaimed[who][id] += amount;
        emit Withdrawn(who, id, amount, txid);
    }

    // --- views -----------------------------------------------------------

    function targetCount() external view returns (uint256) { return targets.length; }

    function balanceOfTarget(uint256 id) external view returns (uint256) {
        return id < targets.length ? targets[id].balance : 0;
    }

    function getTarget(uint256 id) external view returns (Target memory) {
        require(id < targets.length, "No such target");
        return targets[id];
    }
}
