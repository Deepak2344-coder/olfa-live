# Turning on testnet anchoring (optional, free)

Anchoring publishes the ledger's latest fingerprint on a public practice blockchain (Sepolia testnet) so anyone can check it.
It uses play money only. Use a NEW wallet created just for this. Never use a wallet that holds real money.

1. Install a wallet app (for example MetaMask) and create a new account. Switch the network to **Sepolia**.
2. Get free test coins from a Sepolia faucet website (search "Sepolia faucet"). A few cents' worth of play ETH lasts for thousands of anchors.
3. Export that test wallet's private key from the wallet settings. Treat it like a password.
4. Get a free Sepolia node address (an https URL) from a provider such as Alchemy, Infura or publicnode.
5. Put these two lines in `.env` on the server. Never commit this file or share the key:

       OLFA_ANCHOR_RPC=https://your-node-url
       OLFA_ANCHOR_KEY=your_test_wallet_private_key

6. `pip install eth-account` (it is in requirements.txt), then restart Olfa.
7. Submit a report, wait about a minute, then open `/ledger/anchors`. The status becomes "confirmed" and shows a link to the transaction on Sepolia Etherscan.
   The Verify button on a report now also says whether it is covered by an anchor.

If anything is missing or the network is down, Olfa shows "not anchored yet" and keeps working.
