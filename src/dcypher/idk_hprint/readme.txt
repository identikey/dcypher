IdkHprint Productized Size System Demonstration
======================================================================

This demonstrates the productized IdkHprint library with:
- Size names: tiny, small, medium, rack
- Rack scaling: 1 rack, 2 racks, 3 racks, etc.
- HMAC-SHA3-512 chain algorithm
- HMAC-per-character approach
- Base58 encoding with last character selection
- Hierarchical nesting properties
- Underscore separators for easy selection
- Security analysis tools

PRODUCTIZED SIZE SYSTEM DEMONSTRATION
==================================================

Available sizes:
- tiny: [6] (1 segment) - minimal security for testing
- small: [6,8] (2 segments) - basic security for non-critical use
- medium: [6,8,8] (3 segments) - moderate security for general use
- rack: [6,8,8,8] (4 segments) - full pattern for standard security
- Multiple racks: 2 racks = [6,8,8,8,6,8,8,8], etc.

Note: Segments are joined with underscores (_) for easy selection

Size Details:

TINY:
  Pattern: [6]
  Characters: 6
  Display length: 6
  Description: Tiny - minimal security for testing

SMALL:
  Pattern: [6, 8]
  Characters: 14
  Display length: 15
  Description: Small - basic security for non-critical use

MEDIUM:
  Pattern: [6, 8, 8]
  Characters: 22
  Display length: 24
  Description: Medium - moderate security for general use

RACK:
  Pattern: [6, 8, 8, 8]
  Characters: 30
  Display length: 33
  Description: Rack - full pattern for standard security

SIZE-BASED FINGERPRINT GENERATION
==================================================

Public key: b'example_public_key_for_productized_demo'

Fingerprints by size (with underscores for easy selection):

TINY: cY1aKS
  Pattern: [6]
  Security: 17.6 bits
  Length: 6 characters

SMALL: cY1aKS_bo4nhJXc
  Pattern: [6, 8]
  Security: 64.4 bits
  Length: 15 characters

MEDIUM: cY1aKS_bo4nhJXc_jjMsfkAq
  Pattern: [6, 8, 8]
  Security: 111.3 bits
  Length: 24 characters

RACK: cY1aKS_bo4nhJXc_jjMsfkAq_ykYRbL1u
  Pattern: [6, 8, 8, 8]
  Security: 158.2 bits
  Length: 33 characters

RACK SCALING DEMONSTRATION
==================================================

A 'rack' is the full [6,8,8,8] pattern.
Multiple racks provide high security by repeating the pattern.

Public key: b'rack_scaling_demo_key'

Rack-based fingerprints (with underscores):

1 RACK: ix3ycs_cXXmqj4v_sKjaznfq_JUC5hj16
  Pattern: [6, 8, 8, 8]
  Security: 158.2 bits
  Length: 33 characters

2 RACKS: ix3ycs_cXXmqj4v_sKjaznfq_JUC5hj16_TZfNvP_Nxugcd9m_Y4kiKu3b_gbSR3v82
  Pattern: [6, 8, 8, 8, 6, 8, 8, 8]
  Security: 333.9 bits
  Length: 67 characters

3 RACKS: ix3ycs_cXXmqj4v_sKjaznfq_JUC5hj16_TZfNvP_Nxugcd9m_Y4kiKu3b_gbSR3v82_WpDtsu_CsSQVcjv_QxkkisSv_KVxuPyJm
  Pattern: [6, 8, 8, 8, 6, 8, 8, 8, 6, 8, 8, 8]
  Security: 509.6 bits
  Length: 101 characters

4 RACKS: ix3ycs_cXXmqj4v_sKjaznfq_JUC5hj16_TZfNvP_Nxugcd9m_Y4kiKu3b_gbSR3v82_WpDtsu_CsSQVcjv_QxkkisSv_KVxuPyJm_6M2kjZ_DibLXcb8_iPriSG4t_B87anzZq
  Pattern: [6, 8, 8, 8, 6, 8, 8, 8, 6, 8, 8, 8, 6, 8, 8, 8]
  Security: 685.4 bits
  Length: 135 characters

HIERARCHICAL NESTING WITH SIZES
==================================================

TINY: JNTjMw
SMALL: JNTjMw_49Uk5nB4
MEDIUM: JNTjMw_49Uk5nB4_13xUShe7
RACK: JNTjMw_49Uk5nB4_13xUShe7_diueTRRr

Hierarchical nesting verification:
  tiny is prefix of small: True
  small is prefix of medium: True
  medium is prefix of rack: True

DETAILED ALGORITHM EXECUTION
==================================================

Public key: b'detailed_algorithm_demo'
Size: medium

Algorithm execution steps:
  Initial data: 23 bytes (public key)
  Configuration: size 'medium'
  Pattern: [6, 8, 8] (total 22 characters)
  Base pattern [6,8,8,8] cyclical for 3 segments
  Char 1: HMAC(23 bytes) -> 64 bytes -> base58[...a] -> 'a'
  Char 2: HMAC(64 bytes) -> 64 bytes -> base58[...D] -> 'D'
  Char 3: HMAC(64 bytes) -> 64 bytes -> base58[...J] -> 'J'
  Char 4: HMAC(64 bytes) -> 64 bytes -> base58[...6] -> '6'
  Char 5: HMAC(64 bytes) -> 64 bytes -> base58[...J] -> 'J'
  Char 6: HMAC(64 bytes) -> 64 bytes -> base58[...T] -> 'T'
  Char 7: HMAC(64 bytes) -> 64 bytes -> base58[...Q] -> 'Q'
  Char 8: HMAC(64 bytes) -> 64 bytes -> base58[...d] -> 'd'
  Char 9: HMAC(64 bytes) -> 64 bytes -> base58[...t] -> 't'
  Char 10: HMAC(64 bytes) -> 64 bytes -> base58[...h] -> 'h'
  Char 11: HMAC(64 bytes) -> 64 bytes -> base58[...7] -> '7'
  Char 12: HMAC(64 bytes) -> 64 bytes -> base58[...u] -> 'u'
  Char 13: HMAC(64 bytes) -> 64 bytes -> base58[...r] -> 'r'
  Char 14: HMAC(64 bytes) -> 64 bytes -> base58[...p] -> 'p'
  Char 15: HMAC(64 bytes) -> 64 bytes -> base58[...V] -> 'V'
  Char 16: HMAC(64 bytes) -> 64 bytes -> base58[...S] -> 'S'
  Char 17: HMAC(64 bytes) -> 64 bytes -> base58[...i] -> 'i'
  Char 18: HMAC(64 bytes) -> 64 bytes -> base58[...q] -> 'q'
  Char 19: HMAC(64 bytes) -> 64 bytes -> base58[...T] -> 'T'
  Char 20: HMAC(64 bytes) -> 64 bytes -> base58[...C] -> 'C'
  Char 21: HMAC(64 bytes) -> 64 bytes -> base58[...7] -> '7'
  Char 22: HMAC(64 bytes) -> 64 bytes -> base58[...E] -> 'E'
  Segment 1: chars 1-6 -> 'aDJ6JT'
  Segment 2: chars 7-14 -> 'Qdth7urp'
  Segment 3: chars 15-22 -> 'VSiqTC7E'
  Final fingerprint: aDJ6JT_Qdth7urp_VSiqTC7E

Key insights:
- Each character requires a separate HMAC operation
- Takes the LAST character from base58 encoding
- HMAC output becomes input for next character
- Size determines pattern via cyclical [6,8,8,8] sequence
- Segments joined with underscores for easy selection

SECURITY COMPARISON ACROSS SIZES
==================================================

Security Analysis:
Configuration   Pattern                   Security Bits   Level     
---------------------------------------------------------------------------
tiny            [6]                       17.6            LOW       
small           [6, 8]                    64.4            LOW       
medium          [6, 8, 8]                 111.3           MODERATE  
rack            [6, 8, 8, 8]              158.2           HIGH      
2 racks         [6, 8, 8, 8, 6, 8, 8, 8.. 333.9           HIGH      
3 racks         [6, 8, 8, 8, 6, 8, 8, 8.. 509.6           HIGH      
5 racks         [6, 8, 8, 8, 6, 8, 8, 8.. 861.1           HIGH      

Security Level Guidelines:
- LOW (< 80 bits): Testing and development only
- MODERATE (80-127 bits): Non-critical applications
- HIGH (≥ 128 bits): Production and high-security applications

USE CASE RECOMMENDATIONS
==================================================

Recommended configurations by use case:
(All examples use underscores for easy selection)

Development/Testing:
  Size: tiny
  Security: 17.6 bits
  Description: Quick testing, debugging
  Example: diGds3

IoT Device:
  Size: small
  Security: 64.4 bits
  Description: Constrained environments
  Example: K3GZNu_i1m38imP

Mobile App:
  Size: medium
  Security: 111.3 bits
  Description: Balanced security/performance
  Example: cFBvzn_pcziuLqy_iyB1Jnrs

Web Application:
  Size: rack
  Security: 158.2 bits
  Description: Standard web security
  Example: 19VLmn_PHYJc4hQ_ry8tkacV_AiUdzJys

API Authentication:
  Size: rack
  Security: 158.2 bits
  Description: Standard API security
  Example: JaH8qs_WXGQ2M4f_BRH9WAud_vZ1YXsS1

Financial System:
  Racks: 2
  Security: 333.9 bits
  Description: Enhanced security (2 racks)
  Example: RnfYqk_BT2VGWok_rHcoSsGa_Mn558TyW_Loh7rc_k6HPZRQy_2B4HsBAj_Ty5m6tcH

Government/Military:
  Racks: 3
  Security: 509.6 bits
  Description: High security (3 racks)
  Example: 2vjZFB_ahUiGxkq_B3upcrWJ_suK6xqNx_2B649m_jmaoCZv8_WBEr8hiH_LYy3QtK5_1HPPHQ_L4mFubUo_jqwUFxVM_sse5Q5q8

Ultra-secure:
  Racks: 5
  Security: 861.1 bits
  Description: Maximum security (5 racks)
  Example: UeGrmj_USdphcYZ_MwHwNMdh_pL53zoRC_KHbFQ8_oYawdUV4_8r692fXx_qXdJ2MUZ_zbwLZy_CPH2W6nd_Vp2Y82dz_UHjXvzor_jzonQX_xFgwGRwo_XpomWJuB_1rngkrnr_G949mv_YVZzVPPi_aWqTtPeD_6oRrMwH7

SELECTION-FRIENDLY UNDERSCORE FORMAT
==================================================

Underscores make fingerprints easier to select on all platforms:

Desktop Selection:
  KzR7Ma_ZsRzecbs_s8nGy4N4_kibpSdWd
  ↑ Try selecting this - underscores keep it as one unit

Mobile Selection:
  KzR7Ma_ZsRzecbs_s8nGy4N4
  ↑ Try selecting this - underscores keep it as one unit

Copy/Paste Friendly:
  KzR7Ma_ZsRzecbs_s8nGy4N4_kibpSdWd_DzcBQw_yQmz1Sz7_jBBwKF1a_AthYZrJX
  ↑ Try selecting this - underscores keep it as one unit

Benefits of underscore format:
- Easier to select entire fingerprint with double-click
- Better copy/paste experience on mobile devices
- Consistent selection behavior across platforms
- More user-friendly for manual entry when needed

======================================================================
IdkHprint productized size system demonstration completed successfully
======================================================================

Key features:
- Intuitive size names: tiny, small, medium, rack
- Scalable rack system for high security
- Consistent [6,8,8,8] base pattern
- HMAC-per-character cryptographic strength
- Hierarchical nesting for prefix matching
- Configurable security levels via size selection
- Underscore separators for easy selection
- Backward compatibility with num_segments parameter
