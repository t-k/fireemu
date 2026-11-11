# Session clarification for the revision 2 lifetime candidate

This clarifies the explanatory prose accompanying production subject `0ffdcd07fac2fad30bb3d6089b11c2078282c3675be9e4698335e758f244e394` and comparison subject `e082b4f2cef04bf03c05ac5eae3301721078d87d358b06505d18391a5cf98584`. The pinned receipts, generated pages and their checks remain unchanged.

The design finalizes a fresh SMS session only when start succeeds and returns a session. In this production run, every aged start (600, 1800, 3300 and 3900 seconds) was refused. No corresponding session was returned, and every aged finalize was skipped. The measured session ages near zero therefore describe the successful fresh controls, not the refused aged diagnostics. Successful local diagnostics have their own separately recorded session ages.

The six differing rows comprise three direct start disagreements and three consequent accepted-versus-skipped finalize differences. They do not represent six independent bugs or observations of production finalize with an old pending credential. The revision 2 sampled lower bound is absent because none of its aged samples succeeded; this neither retracts revision 1's separate 300-second success nor certifies a combined (300, 600] boundary.

[Production rows](auth-pending-lifetime-boundary.md) and [local comparison](auth-pending-lifetime-boundary-comparison.md) remain candidate records. No TTL or age-causality conclusion, result approval or additional production execution follows from this clarification.
