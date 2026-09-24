"""The verdict vocabulary and the band tables every verdict producer reads.

A risk score runs from 0 (nothing found) to 100. The transaction band table maps it to the
firewall's classification, which is fixed, and to the risk level, whose two thresholds calibration
can move (core/calibration.py starts from the defaults here). An incomplete scan is Unknown whatever
its band: producers mark it with status 'unknown', and it is never classified SAFE.
"""

# Classifications: what the firewall tells the user to do with a transaction.
SAFE = "SAFE"
CAUTION = "CAUTION"
HIGH_RISK = "HIGH_RISK"
BLOCK_RECOMMENDED = "BLOCK_RECOMMENDED"
CLASSIFICATIONS = (SAFE, CAUTION, HIGH_RISK, BLOCK_RECOMMENDED)

# Risk levels: the level a score carries, stored with it in contract_scores.
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
UNKNOWN = "UNKNOWN"
RISK_LEVELS = (LOW, MEDIUM, HIGH, UNKNOWN)

# Agent firewall decisions.
ALLOW = "ALLOW"
WARN = "WARN"
BLOCK = "BLOCK"
AGENT_VERDICTS = (ALLOW, WARN, BLOCK)

# The transaction band table: the lowest score of each classification, highest first. A score is in
# the first band it reaches. Risk level HIGH starts with BLOCK_RECOMMENDED and MEDIUM with CAUTION.
BLOCK_MIN = 71
HIGH_RISK_MIN = 50
CAUTION_MIN = 31
BANDS = (
    (BLOCK_RECOMMENDED, BLOCK_MIN),
    (HIGH_RISK, HIGH_RISK_MIN),
    (CAUTION, CAUTION_MIN),
    (SAFE, 0),
)
# The highest whole score in SAFE.
SAFE_MAX = CAUTION_MIN - 1
_LEVEL_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}

# The contract_scores rows the threat counts count and the threat feed lists.
THREAT_CONDITION = f"risk_level = '{HIGH}'"

# A signature request with no transaction behind it has its own table, and a blind eth_sign
# request scores at least BLIND_SIGN_MIN.
SIGNATURE_BANDS = ((BLOCK_RECOMMENDED, 70), (HIGH_RISK, 40), (CAUTION, 15), (SAFE, 0))
BLIND_SIGN_MIN = 30

# STRICT policy turns an incomplete analysis into a block that reports at least this score.
STRICT_BLOCK_SCORE = 80
# A reverted transaction simulation blocks from this score up; below it a revert is taken as bad
# transaction parameters.
REVERT_BLOCK_MIN = 30

# The agent firewall (agent/policy_engine.py) does not classify. It decides from each agent's own
# thresholds, spending limits and allow and block lists, and incomplete coverage or an unpriced value
# turns an ALLOW into a WARN. Its default thresholds: ALLOW below AGENT_ALLOW_BELOW, BLOCK above
# AGENT_BLOCK_ABOVE, WARN (owner approval) between. For a complete scan with no list match and within
# the spending limits, each classification then meets these decisions: SAFE is ALLOW below 25 and
# WARN from 25; HIGH_RISK is WARN up to 70 and BLOCK above it.
AGENT_ALLOW_BELOW = 25
AGENT_BLOCK_ABOVE = 70
AGENT_DECISIONS_BY_CLASSIFICATION = {
    SAFE: (ALLOW, WARN),
    CAUTION: (WARN,),
    HIGH_RISK: (WARN, BLOCK),
    BLOCK_RECOMMENDED: (BLOCK,),
}


def classify(score, bands=BANDS) -> str:
    """The classification of a score in a band table; anything below the second-lowest band is the lowest."""
    for classification, lowest in bands[:-1]:
        if score >= lowest:
            return classification
    return bands[-1][0]


def level_from_score(score, calibration=None) -> str:
    """The risk level of a score, at the calibrated thresholds when a calibration is given."""
    high = calibration.high_threshold if calibration else BLOCK_MIN
    medium = calibration.medium_threshold if calibration else CAUTION_MIN
    if score >= high:
        return HIGH
    if score >= medium:
        return MEDIUM
    return LOW


def stored_level(score, level) -> str:
    """The level to store and return with a final score: the producer's level raised to the band
    level of the score, never lowered, so an incomplete scan's MEDIUM stays MEDIUM. The raise reads
    the band table, not a calibration, so every stored score in BLOCK_RECOMMENDED is HIGH. UNKNOWN
    is raised only to HIGH."""
    band = level_from_score(score)
    if level not in _LEVEL_RANK:
        return band if band == HIGH else level
    return band if _LEVEL_RANK[band] > _LEVEL_RANK[level] else level
