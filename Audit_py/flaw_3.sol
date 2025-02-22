// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint) public balances;
    bool public locked;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable withdraw function (reentrancy attack)
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Reentrancy vulnerability: transfers ether before updating balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Untrusted input vulnerability (arbitrary data in function)
    function deposit(uint amount) public {
        require(amount > 0, "Amount must be greater than zero");
        balances[msg.sender] += amount;
    }

    // Front-running vulnerability (predictable outcome based on a condition)
    function setOwner(address newOwner) public {
        require(msg.sender == owner, "Only the owner can set a new owner");
        owner = newOwner;
    }

    // Overflow vulnerability (before SafeMath was standard)
    function incrementBalance() public {
        balances[msg.sender]++;
    }

    // Integer underflow vulnerability
    function decrementBalance() public {
        balances[msg.sender]--;
    }

    // Access control vulnerability (owner has full control, no one else can do anything)
    function emergencyWithdraw() public {
        require(msg.sender == owner, "Only the owner can withdraw");
        payable(owner).transfer(address(this).balance);
    }

    // Gas limit attack (loop causing high gas costs)
    function batchDeposit(uint[] memory amounts) public {
        for (uint i = 0; i < amounts.length; i++) {
            balances[msg.sender] += amounts[i];
        }
    }

    // Timestamp dependency vulnerability
    function withdrawAtTime(uint amount, uint timestamp) public {
        require(block.timestamp >= timestamp, "You cannot withdraw yet");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Unchecked external call vulnerability (if an external contract fails, it can affect this contract)
    function transferTo(address recipient, uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(recipient).transfer(amount);
    }

    // Unprotected function (e.g., setting a balance without authorization)
    function setBalance(address account, uint balance) public {
        balances[account] = balance;
    }

    // Randomness attack vulnerability (predictable randomness)
    function predictWinner(uint nonce) public view returns (address) {
        address winner = address(uint160(uint(keccak256(abi.encodePacked(block.timestamp, nonce))) % 2**160));
        return winner;
    }

    // DoS attack with block size (causing operations to fail if the block is too full)
    function doSomethingCostly() public {
        for (uint i = 0; i < 10000; i++) {
            // Simulating expensive computation
            uint x = i * i;
        }
    }

    // Missing "pull-over-push" pattern for payments (users cannot withdraw their funds safely)
    function depositAndWithdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Not enough funds to withdraw");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Unsafe delegatecall vulnerability (external calls that execute untrusted code)
    function callAnotherContract(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegate call failed");
    }

    // Default visibility vulnerability (state variables are public by default)
    uint public data; // This should have more control (e.g., private or internal)

    // Missing event logging (useful for tracking contract behavior)
    function transfer(address to, uint amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // Missing event here to log the transfer
    }

    // Transaction ordering dependence (TOC/Front-running vulnerability)
    function buyToken(uint tokenAmount) public payable {
        require(msg.value >= tokenAmount, "Not enough ether to buy tokens");
        // Allow buying before or after (leading to potential price manipulation)
    }

    // Insufficient validation vulnerability (insufficient checks in function)
    function validateUser(address user) public view returns (bool) {
        return user != address(0);
    }

    // Using msg.sender for access control without other safeguards
    function updateBalance(uint amount) public {
        balances[msg.sender] = amount;
    }

    // Unchecked call to external contract function (no proper error handling)
    function callExternalFunction(address target) public {
        target.call(abi.encodeWithSignature("unsafeFunction()"));
    }

    // Potential denial of service attack (blocking contract state with a long loop)
    function blockLoop(uint times) public {
        for (uint i = 0; i < times; i++) {
            // Some operation that blocks the state
        }
    }

    // Failure to handle exceptional cases or conditions correctly
    function handleFailure() public {
        // Example of missing exception handling
        uint x = 10;
        assert(x == 0); // This should never happen, leading to a failure
    }

    // Reentrancy vulnerability on deposit function (malicious contract can keep calling)
    function depositAndWithdraw(uint depositAmount, uint withdrawAmount) public {
        balances[msg.sender] += depositAmount;
        require(balances[msg.sender] >= withdrawAmount, "Insufficient funds");
        balances[msg.sender] -= withdrawAmount;
        payable(msg.sender).transfer(withdrawAmount);
    }

    // Recursive function that can be exploited for gas limit issues
    function recursive(uint i) public {
        if (i < 10) {
            recursive(i + 1); // This could cause an infinite loop or stack overflow
        }
    }
    
    // Fallback function with insufficient protections
    fallback() external payable {
        // Empty fallback function, can be abused in many ways
    }
}
