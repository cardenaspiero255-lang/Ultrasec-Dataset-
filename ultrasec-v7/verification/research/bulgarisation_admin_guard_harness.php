<?php
/**
 * UltraSec V7 public research: isolated behavior of the exact upstream
 * woo_bg_check_admin_label_actions() function extracted at CI runtime from
 * the official WordPress 3.0.15 release ZIP (never copied to this repo).
 * WordPress guards are deterministic shims, not full WordPress integration.
 */
if ( $argc !== 2 || ! is_file( $argv[1] ) ) {
    fwrite( STDERR, "SOURCE_FRAGMENT_REQUIRED\n" );
    exit( 2 );
}
function __( $message, $domain ) {
    return $message;
}
function wp_verify_nonce( $value, $action ) {
    if ( $action !== 'woo_bg_admin_label' ) {
        throw new RuntimeException( 'WRONG_NONCE_ACTION' );
    }
    return $GLOBALS['research_nonce_allowed'];
}
function current_user_can( $capability ) {
    if ( $capability !== 'manage_woocommerce' ) {
        throw new RuntimeException( 'WRONG_CAPABILITY' );
    }
    return $GLOBALS['research_capability_allowed'];
}
function wp_send_json_error( $message ) {
    throw new RuntimeException( 'DENIED_BY_ORIGINAL_GUARD' );
}
function wp_die() {
    throw new RuntimeException( 'DENIED_BY_WP_DIE' );
}
require $argv[1];
if ( ! function_exists( 'woo_bg_check_admin_label_actions' ) ) {
    fwrite( STDERR, "UPSTREAM_FUNCTION_MISSING\n" );
    exit( 3 );
}
$cases = array(
    array( 'label' => 'no_nonce_no_permission', 'nonce' => false, 'cap' => false, 'should_allow' => false ),
    array( 'label' => 'nonce_only', 'nonce' => true, 'cap' => false, 'should_allow' => false ),
    array( 'label' => 'permission_only', 'nonce' => false, 'cap' => true, 'should_allow' => false ),
    array( 'label' => 'both_valid', 'nonce' => true, 'cap' => true, 'should_allow' => true ),
);
$passed = 0;
foreach ( $cases as $case ) {
    $_REQUEST['nonce'] = 'research-placeholder';
    $GLOBALS['research_nonce_allowed'] = $case['nonce'];
    $GLOBALS['research_capability_allowed'] = $case['cap'];
    $actual_allowed = true;
    try {
        woo_bg_check_admin_label_actions();
    } catch ( RuntimeException $e ) {
        if ( ! in_array( $e->getMessage(), array( 'DENIED_BY_ORIGINAL_GUARD', 'DENIED_BY_WP_DIE' ), true ) ) {
            throw $e;
        }
        $actual_allowed = false;
    }
    $ok = $actual_allowed === $case['should_allow'];
    echo ( $ok ? "PASS " : "FAIL " ) . $case['label'] . "\n";
    if ( $ok ) {
        ++$passed;
    }
}
echo "SUMMARY " . $passed . "/" . count( $cases ) . "\n";
exit( $passed === count( $cases ) ? 0 : 1 );
