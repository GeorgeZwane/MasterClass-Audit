// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint) public balances;

    // Deposit function to store user balances
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Withdrawal function with a vulnerability (reentrancy)
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Transfer funds first (vulnerable to reentrancy attack)
        payable(msg.sender).transfer(_amount);
        
        // Update balance after transferring funds
        balances[msg.sender] -= _amount;
    }
}
