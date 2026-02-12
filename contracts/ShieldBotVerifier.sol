// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ShieldBotVerifier
 * @dev Simple onchain verification contract for ShieldBot scans
 * @notice Records security scans on BNB Chain for transparency
 * 
 * Hackathon: Good Vibes Only - OpenClaw Edition
 * Project: ShieldBot - Your BNB Chain Shield
 * GitHub: https://github.com/Ridwannurudeen/shieldbot
 */
contract ShieldBotVerifier {
    
    // Scan record structure
    struct ScanRecord {
        address scannedAddress;
        uint8 riskLevel;        // 0=LOW, 1=MEDIUM, 2=HIGH, 3=SAFE, 4=WARNING, 5=DANGER
        uint256 timestamp;
        string scanType;        // "contract" or "token"
    }
    
    // Events
    event ScanRecorded(
        address indexed scannedAddress,
        uint8 riskLevel,
        string scanType,
        uint256 timestamp,
        address indexed recorder
    );
    
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    
    // State variables
    address public owner;
    address public verifier;        // Bot address authorized to record scans
    uint256 public totalScans;
    
    // Mapping: address => latest scan record
    mapping(address => ScanRecord) public latestScans;
    
    // Mapping: address => all scan count
    mapping(address => uint256) public scanCount;
    
    // Modifier: Only owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Modifier: Only verifier (bot)
    modifier onlyVerifier() {
        require(msg.sender == verifier, "Not authorized verifier");
        _;
    }
    
    /**
     * @dev Constructor - sets deployer as owner and initial verifier
     */
    constructor() {
        owner = msg.sender;
        verifier = msg.sender;  // Initially owner is also verifier
    }
    
    /**
     * @dev Record a security scan onchain
     * @param _scannedAddress The address that was scanned
     * @param _riskLevel Risk level (0-5)
     * @param _scanType Type of scan ("contract" or "token")
     */
    function recordScan(
        address _scannedAddress,
        uint8 _riskLevel,
        string calldata _scanType
    ) external onlyVerifier {
        require(_scannedAddress != address(0), "Invalid address");
        require(_riskLevel <= 5, "Invalid risk level");
        
        // Create scan record
        ScanRecord memory scan = ScanRecord({
            scannedAddress: _scannedAddress,
            riskLevel: _riskLevel,
            timestamp: block.timestamp,
            scanType: _scanType
        });
        
        // Update mappings
        latestScans[_scannedAddress] = scan;
        scanCount[_scannedAddress]++;
        totalScans++;
        
        // Emit event
        emit ScanRecorded(
            _scannedAddress,
            _riskLevel,
            _scanType,
            block.timestamp,
            msg.sender
        );
    }
    
    /**
     * @dev Batch record multiple scans (gas optimization)
     * @param _addresses Array of addresses scanned
     * @param _riskLevels Array of risk levels
     * @param _scanTypes Array of scan types
     */
    function recordBatchScans(
        address[] calldata _addresses,
        uint8[] calldata _riskLevels,
        string[] calldata _scanTypes
    ) external onlyVerifier {
        require(
            _addresses.length == _riskLevels.length && 
            _addresses.length == _scanTypes.length,
            "Array length mismatch"
        );
        
        for (uint256 i = 0; i < _addresses.length; i++) {
            require(_addresses[i] != address(0), "Invalid address");
            require(_riskLevels[i] <= 5, "Invalid risk level");
            
            ScanRecord memory scan = ScanRecord({
                scannedAddress: _addresses[i],
                riskLevel: _riskLevels[i],
                timestamp: block.timestamp,
                scanType: _scanTypes[i]
            });
            
            latestScans[_addresses[i]] = scan;
            scanCount[_addresses[i]]++;
            totalScans++;
            
            emit ScanRecorded(
                _addresses[i],
                _riskLevels[i],
                _scanTypes[i],
                block.timestamp,
                msg.sender
            );
        }
    }
    
    /**
     * @dev Get latest scan for an address
     * @param _address Address to query
     * @return ScanRecord struct
     */
    function getLatestScan(address _address) external view returns (
        address scannedAddress,
        uint8 riskLevel,
        uint256 timestamp,
        string memory scanType
    ) {
        ScanRecord memory scan = latestScans[_address];
        return (
            scan.scannedAddress,
            scan.riskLevel,
            scan.timestamp,
            scan.scanType
        );
    }
    
    /**
     * @dev Check if address has been scanned
     * @param _address Address to check
     * @return bool True if scanned at least once
     */
    function hasBeenScanned(address _address) external view returns (bool) {
        return latestScans[_address].timestamp != 0;
    }
    
    /**
     * @dev Get scan statistics
     * @return total Total scans recorded
     * @return uniqueAddresses Number of unique addresses scanned
     */
    function getStats() external view returns (uint256 total, uint256 uniqueAddresses) {
        // Note: uniqueAddresses is approximation (would need tracking array for exact count)
        return (totalScans, totalScans); // Simplified for MVP
    }
    
    /**
     * @dev Update verifier address (bot address)
     * @param _newVerifier New verifier address
     */
    function updateVerifier(address _newVerifier) external onlyOwner {
        require(_newVerifier != address(0), "Invalid address");
        address oldVerifier = verifier;
        verifier = _newVerifier;
        emit VerifierUpdated(oldVerifier, _newVerifier);
    }
    
    /**
     * @dev Transfer ownership
     * @param _newOwner New owner address
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid address");
        owner = _newOwner;
    }
    
    /**
     * @dev Risk level decoder
     * @param _level Risk level number
     * @return string Human-readable risk level
     */
    function getRiskLevelName(uint8 _level) external pure returns (string memory) {
        if (_level == 0) return "LOW";
        if (_level == 1) return "MEDIUM";
        if (_level == 2) return "HIGH";
        if (_level == 3) return "SAFE";
        if (_level == 4) return "WARNING";
        if (_level == 5) return "DANGER";
        return "UNKNOWN";
    }
}
