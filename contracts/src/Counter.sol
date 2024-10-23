// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract Settler {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 private constant ORDER_TYPEHASH =
        keccak256(
            "Order(address owner,uint256 nonce,uint8 orderType,address baseCurrency,address quoteCurrency,uint256 quantity,uint256 limit,uint256 stop,uint256 expire,bool full)"
        );
    bytes32 private immutable DOMAIN_SEPARATOR;

    enum OrderType {
        Buy,
        Sell
    }

    struct Order {
        address owner;
        uint nonce;
        OrderType orderType;
        address baseCurrency;
        address quoteCurrency;
        uint quantity;
        uint limit;
        uint stop;
        uint expire;
        bool full;
    }

    struct OngoingOrder {
        address owner;
        uint filledQuantity;
        bool cancelled;
    }

    mapping(bytes orderId => OngoingOrder) public ongoingOrders;
    mapping(address owner => uint nonce) public nonces;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Settler")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // Public Functions

    function execute(
        Order calldata buyOrder,
        Order calldata sellOrder,
        bytes calldata buySignature,
        bytes calldata sellSignature
    ) external {
        // Verify order types
        require(buyOrder.orderType == OrderType.Buy, "Invalid buy order type");
        require(
            sellOrder.orderType == OrderType.Sell,
            "Invalid sell order type"
        );

        // Verify signatures
        require(
            verifyOrderSignature(buyOrder, buySignature),
            "Invalid buy order signature"
        );
        require(
            verifyOrderSignature(sellOrder, sellSignature),
            "Invalid sell order signature"
        );

        // Verify nonces
        require(
            nonces[buyOrder.owner] == buyOrder.nonce,
            "Invalid buy order nonce"
        );
        require(
            nonces[sellOrder.owner] == sellOrder.nonce,
            "Invalid sell order nonce"
        );

        // Increment nonces
        nonces[buyOrder.owner]++;
        nonces[sellOrder.owner]++;
    }

    function cancelOngoingOrder(bytes calldata orderId) external {}

    // Internal Functions

    function verifyOrderSignature(
        Order calldata order,
        bytes calldata signature
    ) internal view returns (bool) {
        bytes32 orderHash = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashOrder(order))
        );

        address signer = recoverSigner(orderHash, signature);
        return signer == order.owner;
    }

    function hashOrder(Order calldata order) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ORDER_TYPEHASH,
                    order.owner,
                    order.nonce,
                    order.orderType,
                    order.baseCurrency,
                    order.quoteCurrency,
                    order.quantity,
                    order.limit,
                    order.stop,
                    order.expire,
                    order.full
                )
            );
    }

    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(hash, v, r, s);
    }
}
