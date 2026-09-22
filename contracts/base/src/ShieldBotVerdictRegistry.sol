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

    /// @notice Largest `recordBatch`. In a full batch, a new subject averages about 72k gas by sharing the recorder
    ///         check and global counter update. The first standalone record on a fresh registry costs more.
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
    /// @notice Emitted when the owner replaces the recorder, including initial assignment at construction.
    /// @param previousRecorder The recorder being replaced, or zero at construction.
    /// @param newRecorder The nonzero address now allowed to record verdicts.
    event RecorderUpdated(address indexed previousRecorder, address indexed newRecorder);

    /// @notice The caller is not the current recorder.
    error NotRecorder();
    /// @notice A subject or recorder address is zero.
    error ZeroAddress();
    /// @notice The evidence hash is zero, which is reserved for subjects never recorded.
    error ZeroEvidenceHash();
    /// @notice A batch contains no entries.
    error EmptyBatch();
    /// @notice A batch exceeds the per-call limit.
    /// @param length The number of entries supplied.
    /// @param max The largest permitted batch.
    error BatchTooLarge(uint256 length, uint256 max);
    /// @notice Ownership cannot be renounced because the owner must remain able to rotate the recorder.
    error OwnershipRenunciationDisabled();

    /// @notice Restricts verdict recording to the current recorder.
    modifier onlyRecorder() {
        if (msg.sender != recorder) revert NotRecorder();
        _;
    }

    /// @param initialRecorder The first recorder address. The deployer becomes the owner.
    constructor(address initialRecorder) Ownable(msg.sender) {
        _setRecorder(initialRecorder);
    }

    /// @notice Replace the recorder, for example after a key rotation or compromise.
    /// @param newRecorder The nonzero address to authorize for future records.
    function setRecorder(address newRecorder) external onlyOwner {
        _setRecorder(newRecorder);
    }

    /// @notice Always reverts to preserve recorder-rotation recovery through the owner.
    function renounceOwnership() public pure override {
        revert OwnershipRenunciationDisabled();
    }

    /// @notice Record one verdict.
    /// @param subject The nonzero token address the verdict is about.
    /// @param verdict ShieldBot's verdict, including UNKNOWN for an incomplete scan.
    /// @param evidenceHash Nonzero keccak256 of the canonical evidence document.
    /// @param observedBlock The Robinhood Chain block observed, or 0 if not tied to one.
    function record(address subject, Verdict verdict, bytes32 evidenceHash, uint64 observedBlock)
        external
        onlyRecorder
    {
        _record(subject, verdict, evidenceHash, observedBlock);
        unchecked {
            ++totalRecords;
        }
    }

    /// @notice Record up to `MAX_BATCH` verdicts in order. Any invalid entry reverts the whole batch.
    /// @param entries The ordered verdicts to record; repeated subjects each count as a record.
    function recordBatch(Entry[] calldata entries) external onlyRecorder {
        uint256 length = entries.length;
        if (length == 0) revert EmptyBatch();
        if (length > MAX_BATCH) revert BatchTooLarge(length, MAX_BATCH);
        for (uint256 i; i < length; ++i) {
            Entry calldata entry = entries[i];
            _record(entry.subject, entry.verdict, entry.evidenceHash, entry.observedBlock);
        }
        unchecked {
            totalRecords += length;
        }
    }

    /// @notice The latest verdict for a subject. A subject never recorded returns an all-zero UNKNOWN record.
    /// @param subject The token address to look up.
    /// @return The latest verdict, observed block, recording timestamp and evidence hash.
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
        }
        emit VerdictRecorded(subject, verdict, evidenceHash, observedBlock, timestamp);
    }

    function _setRecorder(address newRecorder) private {
        if (newRecorder == address(0)) revert ZeroAddress();
        emit RecorderUpdated(recorder, newRecorder);
        recorder = newRecorder;
    }
}
