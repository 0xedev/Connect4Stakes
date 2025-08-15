// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Connect4Stakes
 * - Creator opens a match with an ERC-20 stake
 * - Opponent joins by matching the stake
 * - Winner is finalized either by:
 *    (a) both players submitting the same winner (mutual confirmation), or
 *    (b) an authorized referee (per-match resolver or global resolver/owner)
 * - Deadlines prevent stuck funds:
 *    - If nobody joins by startDeadline => creator refunds
 *    - If not resolved by resolveDeadline => each player can withdraw their own stake
 * - Optional platform fee (bps) taken from total pot on payout
 * - EIP-2612 permit helper for creator UX
 */

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";

contract Connect4Stakes is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ------------------------- Types -------------------------
    enum Status {
        Created,   // creator deposited; waiting for opponent
        Started,   // both deposited; in play
        Resolved,  // winner decided; pot paid
        Refunded   // funds returned (no winner)
    }

    struct Match {
        // identities
        address creator;
        address opponent;        // if zero, it's an open challenge
        address token;           // ERC-20 used
        // money/time
        uint96  stake;           // per player
        uint40  createdAt;
        uint40  startDeadline;   // opponent must join by this time
        uint40  resolveDeadline; // match must be resolved by this time once started
        uint32  resolveWindow;   // seconds to use for resolveDeadline once started
        // control
        address resolver;        // optional per-match referee
        uint16  feeBps;          // snapshot of fee at creation
        Status  status;
        address winner;          // set when Resolved
        // mutual confirmation votes
        address creatorVote;     // zero if no vote; else submitted winner address
        address opponentVote;    // zero if no vote; else submitted winner address
    }

    // ------------------------- Config -------------------------
    address public feeRecipient;
    uint16  public defaultFeeBps = 0;   // can be 0
    uint16  public maxFeeBps = 500;     // <= 5% cap

    mapping(address => bool) public isResolver; // global referees

    // ------------------------- Storage -------------------------
    uint256 public nextMatchId = 1;
    mapping(uint256 => Match) public matches;
    mapping(uint256 => mapping(address => bool)) public withdrawnAfterTimeout; // id => player => withdrew?

    // ------------------------- Events -------------------------
    event MatchCreated(
        uint256 indexed id,
        address indexed creator,
        address indexed token,
        uint256 stake,
        address opponent,
        uint256 startDeadline,
        uint256 resolveWindow,
        address resolver
    );
    event MatchJoined(uint256 indexed id, address indexed opponent, uint256 resolveDeadline);
    event MatchResultSubmitted(uint256 indexed id, address indexed submitter, address winner);
    event MatchResolved(uint256 indexed id, address indexed winner, uint256 prize, uint256 fee);
    event MatchRefunded(uint256 indexed id);
    event ResolverSet(address indexed resolver, bool allowed);
    event FeesUpdated(address indexed recipient, uint16 defaultFeeBps, uint16 maxFeeBps);

    // ------------------------- Constructor -------------------------
    constructor(address _feeRecipient) Ownable(msg.sender) {
        feeRecipient = _feeRecipient;
    }

    // ------------------------- Admin -------------------------
    function setResolver(address account, bool allowed) external onlyOwner {
        isResolver[account] = allowed;
        emit ResolverSet(account, allowed);
    }

    function setFees(address recipient, uint16 _defaultFeeBps, uint16 _maxFeeBps) external onlyOwner {
        require(_maxFeeBps <= 1000, "max >10%");
        require(_defaultFeeBps <= _maxFeeBps, "default > max");
        feeRecipient = recipient;
        defaultFeeBps = _defaultFeeBps;
        maxFeeBps = _maxFeeBps;
        emit FeesUpdated(recipient, _defaultFeeBps, _maxFeeBps);
    }

    // ------------------------- Create / Join -------------------------

    /**
     * @notice Create a match (creator must approve this contract for `stake` first, unless using permit).
     * @param token ERC-20 token address for stakes
     * @param stake Amount each player must deposit (same token decimals for both)
     * @param opponent If nonzero, only this address may join. Zero => open challenge
     * @param startDeadlineSec Seconds from now for the join window (>= 60)
     * @param resolveWindowSec Seconds allowed for resolution after opponent joins (>= 300)
     * @param resolver Optional per-match referee (can be zero)
     */
    function createMatch(
        address token,
        uint96  stake,
        address opponent,
        uint32  startDeadlineSec,
        uint32  resolveWindowSec,
        address resolver
    ) external nonReentrant returns (uint256 id) {
        _validateCreate(stake, startDeadlineSec, resolveWindowSec);

        id = nextMatchId++;
        Match storage m = matches[id];
        m.creator = msg.sender;
        m.opponent = opponent;
        m.token = token;
        m.stake = stake;
        m.createdAt = uint40(block.timestamp);
        m.startDeadline = uint40(block.timestamp + startDeadlineSec);
        m.resolveWindow = resolveWindowSec;
        m.resolver = resolver;
        m.status = Status.Created;
        m.feeBps = defaultFeeBps;

        // pull creator stake
        IERC20(token).safeTransferFrom(msg.sender, address(this), stake);

        emit MatchCreated(
            id, msg.sender, token, stake, opponent, m.startDeadline, m.resolveWindow, resolver
        );
    }

    /**
     * @notice Same as createMatch but uses EIP-2612 permit so the creator can skip an approve tx.
     */
    function createMatchWithPermit(
        address token,
        uint96  stake,
        address opponent,
        uint32  startDeadlineSec,
        uint32  resolveWindowSec,
        address resolver,
        uint256 permitValue,
        uint256 permitDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant returns (uint256 id) {
        _validateCreate(stake, startDeadlineSec, resolveWindowSec);

        // authorize this contract to pull creator's funds
        IERC20Permit(token).permit(msg.sender, address(this), permitValue, permitDeadline, v, r, s);
        require(permitValue >= stake, "permit < stake");

        id = nextMatchId++;
        Match storage m = matches[id];
        m.creator = msg.sender;
        m.opponent = opponent;
        m.token = token;
        m.stake = stake;
        m.createdAt = uint40(block.timestamp);
        m.startDeadline = uint40(block.timestamp + startDeadlineSec);
        m.resolveWindow = resolveWindowSec;
        m.resolver = resolver;
        m.status = Status.Created;
        m.feeBps = defaultFeeBps;

        IERC20(token).safeTransferFrom(msg.sender, address(this), stake);

        emit MatchCreated(
            id, msg.sender, token, stake, opponent, m.startDeadline, m.resolveWindow, resolver
        );
    }

    function _validateCreate(uint96 stake, uint32 startDeadlineSec, uint32 resolveWindowSec) internal pure {
        require(stake > 0, "stake = 0");
        require(startDeadlineSec >= 60, "join window too short");
        require(resolveWindowSec >= 300, "resolve window too short");
    }

    /**
     * @notice Opponent joins an existing match by depositing the same stake.
     *         If opponent was unspecified (open challenge), the caller becomes opponent.
     */
    function joinMatch(uint256 id) external nonReentrant {
        Match storage m = matches[id];
        require(m.status == Status.Created, "not joinable");
        require(block.timestamp <= m.startDeadline, "join window over");

        if (m.opponent != address(0)) {
            require(msg.sender == m.opponent, "not invited");
        } else {
            m.opponent = msg.sender;
        }

        IERC20(m.token).safeTransferFrom(msg.sender, address(this), m.stake);

        m.status = Status.Started;
        m.resolveDeadline = uint40(block.timestamp + m.resolveWindow);

        emit MatchJoined(id, m.opponent, m.resolveDeadline);
    }

    // ------------------------- Result & Resolution -------------------------

    /**
     * @notice Players submit their view of the winner. If both match, payout immediately.
     * @param id Match id
     * @param winner Claimed winner (must be creator or opponent)
     */
    function submitResult(uint256 id, address winner) external nonReentrant {
        Match storage m = matches[id];
        require(m.status == Status.Started, "not started");
        require(block.timestamp <= m.resolveDeadline, "resolution window over");
        require(winner == m.creator || winner == m.opponent, "invalid winner");
        require(msg.sender == m.creator || msg.sender == m.opponent, "not a player");

        if (msg.sender == m.creator) {
            m.creatorVote = winner;
        } else {
            m.opponentVote = winner;
        }

        emit MatchResultSubmitted(id, msg.sender, winner);

        if (m.creatorVote != address(0) && m.creatorVote == m.opponentVote) {
            _payout(id, winner);
        }
    }

    /**
     * @notice Referee path: per-match resolver, global resolver, or owner can finalize anytime after start.
     */
    function resolveByReferee(uint256 id, address winner) external nonReentrant {
        Match storage m = matches[id];
        require(m.status == Status.Started, "not started");
        require(
            msg.sender == m.resolver || isResolver[msg.sender] || msg.sender == owner(),
            "not authorized"
        );
        require(winner == m.creator || winner == m.opponent, "invalid winner");
        _payout(id, winner);
    }

    // ------------------------- Refunds / Safety Rails -------------------------

    /**
     * @notice If nobody joined by startDeadline, creator refunds their stake.
     */
    function refundIfUnjoined(uint256 id) external nonReentrant {
        Match storage m = matches[id];
        require(m.status == Status.Created, "wrong status");
        require(block.timestamp > m.startDeadline, "join window not over");
        require(msg.sender == m.creator, "only creator");

        m.status = Status.Refunded;
        IERC20(m.token).safeTransfer(m.creator, m.stake);
        emit MatchRefunded(id);
    }

    /**
     * @notice If a started match wasn't resolved by resolveDeadline, each player can withdraw their own stake.
     *         When both have withdrawn, status flips to Refunded.
     */
    function withdrawAfterTimeout(uint256 id) external nonReentrant {
        Match storage m = matches[id];
        require(m.status == Status.Started, "wrong status");
        require(block.timestamp > m.resolveDeadline, "resolve window not over");
        require(msg.sender == m.creator || msg.sender == m.opponent, "not a player");
        require(!withdrawnAfterTimeout[id][msg.sender], "already withdrawn");

        withdrawnAfterTimeout[id][msg.sender] = true;
        IERC20(m.token).safeTransfer(msg.sender, m.stake);

        if (withdrawnAfterTimeout[id][m.creator] && withdrawnAfterTimeout[id][m.opponent]) {
            m.status = Status.Refunded;
            emit MatchRefunded(id);
        }
    }

    // ------------------------- Views -------------------------
    function getMatch(uint256 id) external view returns (Match memory) {
        return matches[id];
    }

    function pot(uint256 id) public view returns (uint256) {
        Match storage m = matches[id];
        if (m.status == Status.Created) return uint256(m.stake);      // only creator funded
        if (m.status == Status.Started) return uint256(m.stake) * 2;  // both funded
        return 0;
    }

    // ------------------------- Internal -------------------------
    function _payout(uint256 id, address winner) internal {
        Match storage m = matches[id];
        require(m.status == Status.Started, "not active");
        m.status = Status.Resolved;
        m.winner = winner;

        uint256 total = uint256(m.stake) * 2;
        uint256 fee = 0;

        if (feeRecipient != address(0) && m.feeBps > 0) {
            require(m.feeBps <= maxFeeBps, "fee > max");
            fee = (total * m.feeBps) / 10_000;
            IERC20(m.token).safeTransfer(feeRecipient, fee);
        }

        uint256 prize = total - fee;
        IERC20(m.token).safeTransfer(winner, prize);

        emit MatchResolved(id, winner, prize, fee);
    }
}
