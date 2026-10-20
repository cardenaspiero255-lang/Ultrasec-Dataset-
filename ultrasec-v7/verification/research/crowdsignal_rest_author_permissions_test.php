<?php
/**
 * UltraSec V7 public research test.
 * A role with publish_posts must not authorize creating/updating unrelated surveys.
 * Calls REST permission callbacks only; never mutates content or calls the API.
 */
class UltraSec_V7_Rest_Author_Test extends WP_UnitTestCase {
    private function assert_author_not_allowed( $kind, $method, $suffix ) {
        $author = self::factory()->user->create( array( 'role' => 'author' ) );
        wp_set_current_user( $author );
        $this->assertTrue( current_user_can( 'publish_posts' ), 'Author role precondition failed' );
        $classname = 'Crowdsignal_Forms\\Rest_Api\\Controllers\\' .
            ( $kind === 'nps' ? 'Nps_Controller' : 'Feedback_Controller' );
        $this->assertTrue( class_exists( $classname ) );
        // rest_get_server() invokes rest_api_init and registers upstream routes exactly once.
        // Calling register_routes() here would trigger WordPress's incorrect-usage detector.
        $routes = rest_get_server()->get_routes();
        $response_route = '/crowdsignal-forms/v1/' . $kind . '/(?P<survey_id>\\d+)/response';
        $this->assertArrayHasKey( $response_route, $routes, 'Plugin routes must be loaded' );
        $path = '/crowdsignal-forms/v1/' . $kind . $suffix;
        if ( ! isset( $routes[$path] ) ) {
            return; // Version 1.8.0 removes mutation routes while retaining response route.
        }
        $found = false;
        foreach ( $routes[$path] as $handler ) {
            if ( ! isset( $handler['methods'], $handler['permission_callback'] ) ) {
                continue;
            }
            $methods = is_array( $handler['methods'] )
                ? $handler['methods'] : explode( ',', $handler['methods'] );
            if ( ! in_array( $method, $methods, true ) && ! array_key_exists( $method, $methods ) ) {
                continue;
            }
            $found = true;
            $allowed = call_user_func(
                $handler['permission_callback'],
                new WP_REST_Request( $method, $path )
            );
            $this->assertFalse( $allowed, 'Author permitted to mutate ' . $method . ' ' . $path );
        }
        $this->assertTrue( $found, 'Expected mutation method on registered path' );
    }

    public function test_nps_create_not_allowed_for_author() {
        $this->assert_author_not_allowed( 'nps', 'POST', '' );
    }
    public function test_nps_update_not_allowed_for_author() {
        $this->assert_author_not_allowed( 'nps', 'PUT', '/(?P<survey_id>\\d+)' );
    }
    public function test_feedback_create_not_allowed_for_author() {
        $this->assert_author_not_allowed( 'feedback', 'POST', '' );
    }
    public function test_feedback_update_not_allowed_for_author() {
        $this->assert_author_not_allowed( 'feedback', 'PUT', '/(?P<survey_id>\\d+)' );
    }
}
