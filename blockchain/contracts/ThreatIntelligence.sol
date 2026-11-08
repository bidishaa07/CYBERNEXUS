// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @notice Stores non-sensitive cryptographic commitments for threat reports.
/// Report content and evidence remain off-chain.
contract ThreatIntelligence is AccessControl {
    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");

    enum ValidationStatus { UNSET, PENDING, VALIDATED, REJECTED, DISPUTED }

    struct Report {
        bool exists;
        bytes32 latestRevisionId;
        uint64 createdAt;
        uint64 revisionCount;
        bool disputed;
    }

    struct Revision {
        bytes32 revisionId;
        bytes32 commitment;
        uint64 revisionNumber;
        uint64 createdAt;
        address author;
        string metadata;
    }

    mapping(bytes32 => Report) private reports;
    mapping(bytes32 => Revision[]) private revisions;
    mapping(bytes32 => mapping(bytes32 => bool)) public revisionExists;
    mapping(bytes32 => ValidationStatus) public validationStatus;

    event ReportAnchored(bytes32 indexed reportId, bytes32 indexed revisionId, bytes32 commitment, address indexed author, uint64 timestamp);
    event RevisionAnchored(bytes32 indexed reportId, bytes32 indexed revisionId, uint64 revisionNumber, bytes32 commitment, address indexed author, uint64 timestamp);
    event ValidationStatusChanged(bytes32 indexed reportId, ValidationStatus status, address indexed actor, string reason);
    event DisputeRecorded(bytes32 indexed reportId, address indexed actor, string reason, uint64 timestamp);
    event DisputeResolved(bytes32 indexed reportId, address indexed actor, string resolution, uint64 timestamp);

    constructor(address initialAdmin) {
        require(initialAdmin != address(0), "admin is zero");
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(REPORTER_ROLE, initialAdmin);
    }

    function grantReporter(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(account != address(0), "reporter is zero");
        grantRole(REPORTER_ROLE, account);
    }

    function anchorReport(bytes32 reportId, bytes32 commitment, string calldata metadata)
        external onlyRole(REPORTER_ROLE) returns (bytes32 revisionId)
    {
        require(reportId != bytes32(0), "report id is zero");
        require(commitment != bytes32(0), "commitment is zero");
        require(!reports[reportId].exists, "report already anchored");
        reports[reportId] = Report(true, bytes32(0), uint64(block.timestamp), 0, false);
        revisionId = _appendRevision(reportId, commitment, metadata);
        emit ReportAnchored(reportId, revisionId, commitment, msg.sender, uint64(block.timestamp));
    }

    function addRevision(bytes32 reportId, bytes32 commitment, string calldata metadata)
        external onlyRole(REPORTER_ROLE) returns (bytes32 revisionId)
    {
        require(reports[reportId].exists, "report not found");
        require(commitment != bytes32(0), "commitment is zero");
        revisionId = _appendRevision(reportId, commitment, metadata);
    }

    function _appendRevision(bytes32 reportId, bytes32 commitment, string calldata metadata) internal returns (bytes32 revisionId) {
        Report storage report = reports[reportId];
        uint64 number = report.revisionCount + 1;
        revisionId = keccak256(abi.encode("CYBERNEXUS:REPORT_REVISION:v1", reportId, number, commitment));
        require(!revisionExists[reportId][revisionId], "revision already exists");
        revisions[reportId].push(Revision(revisionId, commitment, number, uint64(block.timestamp), msg.sender, metadata));
        revisionExists[reportId][revisionId] = true;
        report.latestRevisionId = revisionId;
        report.revisionCount = number;
        emit RevisionAnchored(reportId, revisionId, number, commitment, msg.sender, uint64(block.timestamp));
    }

    function setValidationStatus(bytes32 reportId, ValidationStatus status, string calldata reason)
        external onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(reports[reportId].exists, "report not found");
        validationStatus[reportId] = status;
        emit ValidationStatusChanged(reportId, status, msg.sender, reason);
    }

    function recordDispute(bytes32 reportId, string calldata reason) external onlyRole(REPORTER_ROLE) {
        require(reports[reportId].exists, "report not found");
        reports[reportId].disputed = true;
        validationStatus[reportId] = ValidationStatus.DISPUTED;
        emit DisputeRecorded(reportId, msg.sender, reason, uint64(block.timestamp));
    }

    function resolveDispute(bytes32 reportId, string calldata resolution) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(reports[reportId].exists, "report not found");
        reports[reportId].disputed = false;
        emit DisputeResolved(reportId, msg.sender, resolution, uint64(block.timestamp));
    }

    function getReport(bytes32 reportId) external view returns (Report memory) {
        require(reports[reportId].exists, "report not found");
        return reports[reportId];
    }

    function getRevision(bytes32 reportId, uint256 index) external view returns (Revision memory) {
        require(index < revisions[reportId].length, "revision index out of range");
        return revisions[reportId][index];
    }

    function getRevisionCount(bytes32 reportId) external view returns (uint256) {
        return revisions[reportId].length;
    }

    function verifyCommitment(bytes32 reportId, bytes32 revisionId, bytes32 candidate) external view returns (bool) {
        for (uint256 i = 0; i < revisions[reportId].length; i++) {
            Revision memory revision = revisions[reportId][i];
            if (revision.revisionId == revisionId) return revision.commitment == candidate;
        }
        return false;
    }
}
