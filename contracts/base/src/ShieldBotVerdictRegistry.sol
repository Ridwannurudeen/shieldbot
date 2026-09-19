// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title ShieldBotVerdictRegistry
/// @notice Public, tamper-evident log of ShieldBot's token verdicts on Robinhood Chain.
/// @dev Every record commits to an off-chain evidence document by its keccak256 hash. Anyone can fetch the
///      document, re-hash it and compare it with the `VerdictRecorded` event. The registry holds no funds, makes
///      no external calls and is not upgradeable. The owner only rotates the recorder; the recorder only records.
contract ShieldBotVerdictRegistry is Ownable2Step {
    /// @notice ShieldBot's verdict on a token.
    /// @dev UNKNOWN is the zero value, so a subject that was never recorded reads as UNKNOWN, never as LOW.
    ///      UNKNOWN  - the scan was incomplete; it makes no claim about safety.
    ///      LOW, MEDIUM, HIGH - the risk band of a complete scan.
    ///      HONEYPOT - a buy-then-sell simulation proved holders cannot sell, whatever else is unknown.
    ///      An out-of-range value is rejected by the ABI decoder before any function body runs.
    enum Verdict {
        UNKNOWN,
        LOW,
        MEDIUM,
        HIGH,
        HONEYPOT
    }

    /// @notice The latest verdict stored for a subject (two storage slots).
    struct Record {
        Verdict verdict;
        uint64 observedBlock;
        uint64 timestamp;
        bytes32 evidenceHash;
    }

    /// @notice One `recordBatch` entry, with the same fields as `record`.
    struct Entry {
        address subject;
        Verdict verdict;
        bytes32 evidenceHash;
        uint64 observedBlock;
    }

    /// @notice Largest `recordBatch`. A first record for a subject costs about 72k gas; a full batch of new
    ///         subjects measured 3.62M gas in the Foundry gas report, which bounds any single call.
    uint256 public constant MAX_BATCH = 50;

    /// @notice The only address allowed to record verdicts. Rotated by the owner.
    address public recorder;
    /// @notice Number of verdicts ever recorded, across all subjects.
    uint256 public totalRecords;
    /// @notice Number of verdicts ever recorded for a subject.
    mapping(address subject => uint256 count) public recordCount;

    mapping(address subject => Record record) private _latest;

    /// @notice Emitted for every recorded verdict.
    /// @param subject The token the verdict is about.
    /// @param verdict ShieldBot's verdict.
    /// @param evidenceHash keccak256 of the canonical evidence document.
    /// @param observedBlock The Robinhood Chain block the evidence was observed at, 0 if not tied to one.
    ///        Supplied by the recorder and not compared with `block.number`, which on Arbitrum chains is the
    ///        parent-chain block number.
    /// @param timestamp `block.timestamp` of the recording transaction.
    event VerdictRecorded(
        address indexed subject,
        Verdict indexed verdict,
        bytes32 indexed evidenceHash,
        uint64 observedBlock,
        uint64 timestamp
    );
    event RecorderUpdated(address indexed previousRecorder, address indexed newRecorder);

    error NotRecorder();
    error ZeroAddress();
    error ZeroEvidenceHash();
    error EmptyBatch();
    error BatchTooLarge(uint256 length, uint256 max);

    modifier onlyRecorder() {
        if (msg.sender != recorder) revert NotRecorder();
        _;
    }

    /// @param initialRecorder The first recorder address. The deployer becomes the owner.
    constructor(address initialRecorder) Ownable(msg.sender) {
        _setRecorder(initialRecorder);
    }

    /// @notice Replace the recorder, for example after a key rotation or compromise.
    function setRecorder(address newRecorder) external onlyOwner {
        _setRecorder(newRecorder);
    }

    /// @notice Record one verdict.
    function record(address subject, Verdict verdict, bytes32 evidenceHash, uint64 observedBlock)
        external
        onlyRecorder
    {
        _record(subject, verdict, evidenceHash, observedBlock);
    }

    /// @notice Record up to `MAX_BATCH` verdicts in order. Any invalid entry reverts the whole batch.
    function recordBatch(Entry[] calldata entries) external onlyRecorder {
        uint256 length = entries.length;
        if (length == 0) revert EmptyBatch();
        if (length > MAX_BATCH) revert BatchTooLarge(length, MAX_BATCH);
        for (uint256 i; i < length; ++i) {
            Entry calldata entry = entries[i];
            _record(entry.subject, entry.verdict, entry.evidenceHash, entry.observedBlock);
        }
    }

    /// @notice The latest verdict for a subject. A subject never recorded returns an all-zero UNKNOWN record.
    function latestRecord(address subject) external view returns (Record memory) {
        return _latest[subject];
    }

    function _record(address subject, Verdict verdict, bytes32 evidenceHash, uint64 observedBlock) private {
        if (subject == address(0)) revert ZeroAddress();
        if (evidenceHash == bytes32(0)) revert ZeroEvidenceHash();
        uint64 timestamp = uint64(block.timestamp);
        _latest[subject] =
            Record({verdict: verdict, observedBlock: observedBlock, timestamp: timestamp, evidenceHash: evidenceHash});
        unchecked {
            ++recordCount[subject];
            ++totalRecords;
        }
        emit VerdictRecorded(subject, verdict, evidenceHash, observedBlock, timestamp);
    }

    function _setRecorder(address newRecorder) private {
        if (newRecorder == address(0)) revert ZeroAddress();
        emit RecorderUpdated(recorder, newRecorder);
        recorder = newRecorder;
    }
}
