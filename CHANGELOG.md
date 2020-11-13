# 3.0.0 - Oct 13, 2020

- **Bump MSRV to 1.29**

# 2.0.0 - Oct 1, 2020

- Changes to the miniscript type system to detect an invalid
  combination of heightlocks and timelocks
     - Lift miniscripts can now fail. Earlier it always succeeded and gave
       the resulting Semantic Policy
     - Compiler will not compile policies that contain at least one
     unspendable path
- Added support for Descriptor PublicKeys(xpub)
- Added a generic psbt finalizer and extractor
- Updated Satisfaction API for checking time/height before setting satisfaction
- Added a policy entailment API for more miniscript semantic analysis

# 1.0.0 - July 6, 2020

- Added the following aliases to miniscript for ease of operations 
	- Rename `pk` to `pk_k`
	- Rename `thresh_m` to `multi`
	- Add alias `pk(K)` = `c:pk_k(K)`
	- Add alias `pkh(K)` = `c:pk_h(K)`
- Fixed Miniscript parser bugs when decoding Hashlocks
- Added scriptContext(`Legacy` and `Segwitv0`) to Miniscript. 
- Miscellaneous fixes against DoS attacks for heavy nesting.
- Fixed Satisfier bug that caused flipping of arguments for `and_v` and `and_n` and `and_or`

