<?php
/**
 * Safe WordPress + WooCommerce integration witness for CVE-2024-2395 research.
 * Call the original registered admin-ajax CVC delete-label handler.
 * Absolutely no outgoing requests to courier providers are permitted:
 * pre_http_request triggers a local exception before the HTTP transport.
 * A genuine missing nonce must fail before reaching a courier in the fixed build.
 * This is not a real attacker exploit and has no live carrier credentials.
 */
class UltraSec_Bulgarisation_Csrf_WP_Test extends WP_UnitTestCase {
    private $blocked_requests = array();

    public function set_up(): void {
        parent::set_up();
        if ( ! class_exists( '\WooCommerce' ) || ! function_exists( 'wc_create_order' ) ) {
            throw new RuntimeException( 'WOOCOMMERCE_NOT_LOADED' );
        }
        if ( ! function_exists( 'woo_bg' ) || ! class_exists( '\Woo_BG\Admin\CVC' ) ) {
            throw new RuntimeException( 'BULGARISATION_NOT_LOADED' );
        }
        if ( ! has_action( 'wp_ajax_woo_bg_cvc_delete_label' ) ) {
            new \Woo_BG\Admin\CVC();
        }
        $this->assertNotFalse( has_action( 'wp_ajax_woo_bg_cvc_delete_label' ) );

        add_filter( 'pre_http_request', array( $this, 'forbid_all_http' ), -999, 3 );
        add_filter( 'wp_die_ajax_handler', array( $this, 'intercept_wp_die' ), -999 );
        add_filter( 'wp_die_handler', array( $this, 'intercept_wp_die' ), -999 );
    }

    public function tear_down(): void {
        remove_filter( 'pre_http_request', array( $this, 'forbid_all_http' ), -999 );
        remove_filter( 'wp_die_ajax_handler', array( $this, 'intercept_wp_die' ), -999 );
        remove_filter( 'wp_die_handler', array( $this, 'intercept_wp_die' ), -999 );
        unset( $_REQUEST['orderId'], $_REQUEST['shipmentStatus'], $_REQUEST['nonce'] );
        parent::tear_down();
    }

    public function forbid_all_http( $preempt, $request, $url ) {
        $this->blocked_requests[] = $url;
        // This aborts before the WordPress HTTP transport can emit a request.
        throw new \RuntimeException( 'BLOCKED_OUTBOUND_PROVIDER_REQUEST' );
    }

    public function intercept_wp_die() {
        return array( $this, 'fake_wp_die' );
    }

    public function fake_wp_die( $message = '', $title = '', $args = array() ) {
        throw new \RuntimeException( 'BLOCKED_BY_WORDPRESS_GUARD' );
    }

    /**
     * Both versions are run against the SAME security policy:
     * wp_ajax handler must reject a request lacking a real WordPress nonce.
     * Version 3.0.14 is expected to trigger network tripwire (RED).
     * Version 3.0.15 should trigger wp_die before any network request (GREEN).
     */
    public function test_shop_manager_without_nonce_does_not_reach_carrier_api() {
        // WooCommerce wasn't activated via the normal plugin installer on WP test bootstrap;
        // give the standard administrator its legitimate WooCommerce capability explicitly.
        $administrator_role = get_role( 'administrator' );
        $this->assertNotNull( $administrator_role );
        $administrator_role->add_cap( 'manage_woocommerce' );
        $manager = self::factory()->user->create( array( 'role' => 'administrator' ) );
        wp_set_current_user( $manager );
        $this->assertTrue( current_user_can( 'manage_woocommerce' ) );
        $order = wc_create_order();
        $this->assertTrue( is_a( $order, '\WC_Order' ) );
        $_REQUEST['orderId'] = $order->get_id();
        $_REQUEST['shipmentStatus'] = array( 'wb' => 'LOCAL_TEST_ONLY' );
        unset( $_REQUEST['nonce'] );
        $reason = '';
        ob_start();
        try {
            do_action( 'wp_ajax_woo_bg_cvc_delete_label' );
            $reason = 'RETURNED_WITHOUT_GUARD';
        } catch ( \Throwable $e ) {
            $reason = $e->getMessage();
        } finally {
            ob_end_clean();
        }
        echo "SECURITY_TERMINATION=" . $reason . "\n";
        echo "BLOCKED_HTTP_ATTEMPTS=" . count( $this->blocked_requests ) . "\n";
        $this->assertSame(
            'BLOCKED_BY_WORDPRESS_GUARD',
            $reason,
            'Missing nonce must be rejected before side effects or reaching courier network'
        );
        $this->assertCount( 0, $this->blocked_requests );
    }
}
