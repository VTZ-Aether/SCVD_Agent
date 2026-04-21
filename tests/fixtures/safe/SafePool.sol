pragma solidity ^0.8.20;

contract SafePool {
    uint256 public idleBalance0;
    uint256 public activeBalance0;
    uint256 public activeBalance1;
    uint256 public totalSupply;
    uint256 public density0;
    uint256 public density1;

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return b == 0 ? 0 : (a + b - 1) / b;
    }

    function withdraw(uint256 shares) external {
        require(totalSupply > 0, "zero supply");
        uint256 dec = ceilDiv(idleBalance0 * shares, totalSupply);
        idleBalance0 = idleBalance0 - dec;
        activeBalance0 = activeBalance0 - dec;
        totalSupply = totalSupply - shares;
    }

    function quoteLiquidity() external view returns (uint256) {
        require(density0 > 0 && density1 > 0, "density");
        uint256 L0 = activeBalance0 / density0;
        uint256 L1 = activeBalance1 / density1;
        return L0 < L1 ? L0 : L1;
    }
}
