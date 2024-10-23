// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

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
        uint256 nonce;
        OrderType orderType;
        address baseCurrency;
        address quoteCurrency;
        uint256 quantity;
        uint256 limit;
        uint256 stop;
        uint256 expire;
        bool full;
    }

    struct OngoingOrder {
        address owner;
        uint256 filledQuantity;
        bool cancelled;
    }

    mapping(bytes32 orderId => OngoingOrder) public ongoingOrders;
    mapping(address owner => uint256 nonce) public nonces;

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
        // TODO: Verify priviledged executor

        // Verify order types
        require(buyOrder.orderType == OrderType.Buy, "Invalid buy order type");
        require(
            sellOrder.orderType == OrderType.Sell,
            "Invalid sell order type"
        );

        bytes32 buyOrderHash = hashOrder(buyOrder);
        bytes32 sellOrderHash = hashOrder(sellOrder);

        // Verify signatures
        require(
            verifyOrderSignature(buyOrderHash, buyOrder.owner, buySignature),
            "Invalid sell order signature"
        );
        require(
            verifyOrderSignature(sellOrderHash, sellOrder.owner, sellSignature),
            "Invalid sell order signature"
        );

        // Verify matching currency pairs
        require(
            buyOrder.baseCurrency == sellOrder.baseCurrency &&
                buyOrder.quoteCurrency == sellOrder.quoteCurrency,
            "Currency pairs do not match"
        );

        // Verify order expiration
        require(buyOrder.expire > block.timestamp, "Buy order has expired");
        require(sellOrder.expire > block.timestamp, "Sell order has expired");

        // Verify order quotes
        require(
            buyOrder.limit >= sellOrder.limit &&
                buyOrder.stop <= sellOrder.stop,
            "Invalid order quotes"
        );

        // Calculate quantities and price
        (
            uint256 baseQuantity,
            uint256 quoteQuantity,
            // uint256 executionPrice
        ) = calculateExecutionQuantities(buyOrder, sellOrder);

        // TODO: Verify against nonce
        // TODO: Verify against full fill flag

        // Verify against ongoing orders
        require(
            verifyOngoingOrder(buyOrderHash, buyOrder.quantity, baseQuantity),
            "Ongoing order clash"
        );
        require(
            verifyOngoingOrder(sellOrderHash, sellOrder.quantity, baseQuantity),
            "Ongoing order clash"
        );

        // Verify balances
        require(
            IERC20(buyOrder.quoteCurrency).balanceOf(buyOrder.owner) >=
                quoteQuantity,
            "Insufficient buyer balance"
        );
        require(
            IERC20(sellOrder.baseCurrency).balanceOf(sellOrder.owner) >=
                baseQuantity,
            "Insufficient seller balance"
        );

        // Increment nonces
        nonces[buyOrder.owner]++;
        nonces[sellOrder.owner]++;

        if (baseQuantity < sellOrder.quantity) {}

        // Transfer asserts
        IERC20(buyOrder.quoteCurrency).transferFrom(
            buyOrder.owner,
            sellOrder.owner,
            quoteQuantity
        );
        IERC20(sellOrder.baseCurrency).transferFrom(
            sellOrder.owner,
            buyOrder.owner,
            baseQuantity
        );
    }

    function cancelOngoingOrder(bytes32 orderId) external {
        OngoingOrder storage ongoingOrder = ongoingOrders[orderId];

        require(ongoingOrder.owner != address(0), "Missing order");
        require(!ongoingOrder.cancelled, "Order already cancelled");

        ongoingOrder.cancelled = true;
    }

    // View functions

    function calculateExecutionPrice(
        Order calldata buyOrder,
        Order calldata sellOrder
    ) public pure returns (uint256) {
        uint256 average = (buyOrder.limit + sellOrder.limit) / 2;

        if (average > buyOrder.limit) {
            return buyOrder.limit;
        }

        if (average < buyOrder.stop) {
            return buyOrder.stop;
        }

        if (average < sellOrder.limit) {
            return sellOrder.limit;
        }

        if (average > sellOrder.stop) {
            return sellOrder.stop;
        }

        return average;
    }

    function calculateExecutionQuantities(
        Order calldata buyOrder,
        Order calldata sellOrder
    )
        public
        pure
        returns (
            uint256 baseQuantity,
            uint256 quoteQuantity,
            uint256 executionPrice
        )
    {
        baseQuantity = buyOrder.quantity < sellOrder.quantity
            ? buyOrder.quantity
            : sellOrder.quantity;
        executionPrice = calculateExecutionPrice(buyOrder, sellOrder);
        quoteQuantity = baseQuantity * executionPrice;
    }

    function verifyOngoingOrder(
        bytes32 orderHash,
        uint256 orderQuantity,
        uint256 executionQuantity
    ) public view returns (bool) {
        return
            (executionQuantity + ongoingOrders[orderHash].filledQuantity) <=
            orderQuantity &&
            !ongoingOrders[orderHash].cancelled;
    }

    function verifyOrderSignature(
        bytes32 orderHash,
        address orderOwner,
        bytes calldata signature
    ) public view returns (bool) {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, orderHash)
        );

        address signer = ECDSA.recover(digest, signature);
        return signer == orderOwner;
    }

    function hashOrder(Order calldata order) public pure returns (bytes32) {
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
}
