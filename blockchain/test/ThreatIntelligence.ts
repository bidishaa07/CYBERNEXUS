import { expect } from "chai";
import { ethers } from "hardhat";

describe("ThreatIntelligence", function () {
  async function deployed() {
    const [admin, reporter, other] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("ThreatIntelligence");
    const contract = await factory.deploy(admin.address);
    await contract.waitForDeployment();
    return { contract, admin, reporter, other };
  }

  it("anchors, verifies and prevents duplicate reports", async function () {
    const { contract, admin } = await deployed();
    const report = ethers.id("report-1");
    const commitment = ethers.id("commitment-1");
    await expect(contract.anchorReport(report, commitment, "minimal metadata")).to.emit(contract, "ReportAnchored");
    const stored = await contract.getReport(report);
    expect(stored.revisionCount).to.equal(1n);
    expect(await contract.verifyCommitment(report, stored.latestRevisionId, commitment)).to.equal(true);
    expect(await contract.verifyCommitment(report, stored.latestRevisionId, ethers.id("changed"))).to.equal(false);
    await expect(contract.anchorReport(report, commitment, "duplicate")).to.be.revertedWith("report already anchored");
  });

  it("keeps revision history and emits validation/dispute events", async function () {
    const { contract, admin } = await deployed();
    const report = ethers.id("report-2");
    await contract.anchorReport(report, ethers.id("v1"), "v1");
    await expect(contract.addRevision(report, ethers.id("v2"), "v2")).to.emit(contract, "RevisionAnchored");
    expect(await contract.getRevisionCount(report)).to.equal(2n);
    await expect(contract.setValidationStatus(report, 2, "validated")).to.emit(contract, "ValidationStatusChanged");
    await expect(contract.recordDispute(report, "needs review")).to.emit(contract, "DisputeRecorded");
    await expect(contract.resolveDispute(report, "resolved")).to.emit(contract, "DisputeResolved");
  });

  it("rejects unauthorized writes and invalid inputs", async function () {
    const { contract, other } = await deployed();
    const report = ethers.id("report-3");
    await expect(contract.connect(other).anchorReport(report, ethers.id("x"), "metadata")).to.be.reverted;
    await expect(contract.anchorReport(ethers.ZeroHash, ethers.id("x"), "metadata")).to.be.revertedWith("report id is zero");
    await expect(contract.anchorReport(report, ethers.ZeroHash, "metadata")).to.be.revertedWith("commitment is zero");
  });
});
