require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-chai-matchers");

/** Exact versions are reported in Table VI of the paper. */
module.exports = {
  solidity: {
    version: "0.8.30",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "prague",
    },
  },
  networks: {
    hardhat: {
      hardfork: "osaka",
      chainId: 31337,
      allowUnlimitedContractSize: false,
      blockGasLimit: 60_000_000,
    },
    localhost: { url: "http://127.0.0.1:8545", chainId: 31337 },
  },
};
