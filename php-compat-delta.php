<?php
/**
 * Plugin Name: PHP Compatibility Delta
 * Description: Scan WordPress plugins for new PHPCompatibility issues between the current runtime PHP and a single target version. Outputs inline HTML; supports warnings opt-in. Stores a note next to each plugin name with the latest scan result.
 * Version: 0.1.0
 * Author: Brightleaf
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; }

/**
 * Main plugin class for PHP Compatibility Delta.
 *
 * Provides an admin Tools page to scan installed plugins for new PHPCompatibility
 * issues between the current runtime PHP version and a chosen target PHP version.
 * Also stores a summary next to each plugin on the plugins list page.
 */
class PCD_Plugin {
	const OPT_LAST_SCAN = 'pcd_last_scan_results';

	/**
     * Hook WordPress actions/filters for the plugin lifecycle.
     *
     * - Adds the Tools page.
     * - Boots any dependencies if needed.
     * - Outputs small CSS in admin.
     * - Adds plugin list badges.
     * - Registers AJAX handler for scans.
     */
	public static function init(): void {
		add_action( 'admin_menu', [ __CLASS__, 'register_tools_page' ] );
		add_action( 'admin_init', [ __CLASS__, 'maybe_bootstrap' ] );
		add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_assets' ] );
		add_filter( 'plugin_row_meta', [ __CLASS__, 'plugin_row_meta_note' ], 10, 2 );
		add_action( 'wp_ajax_pcd_scan', [ __CLASS__, 'ajax_scan' ] );
	}

	/**
     * Bootstrap hook for future dependency checks.
     *
     * Currently a placeholder.
     */
 	public static function maybe_bootstrap(): void {
		// Placeholder for future dependency checks if needed.
	}

	/**
     * Register the Tools page under Tools > PHP Compatibility Delta.
     *
     * Checks user capability before registering the page.
     */
 	public static function register_tools_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		add_management_page(
			'PHP Compatibility Delta',
			'PHP Compatibility Delta',
			'manage_options',
			'php-compat-delta',
			[ __CLASS__, 'render_page' ]
		);
	}

	/**
     * HTML-escape a string with ENT_QUOTES and UTF-8.
     *
     * @param string $s Raw string.
     * @return string Escaped string safe for HTML output.
     */
 	private static function h( string $s ): string {
		return htmlspecialchars( $s, ENT_QUOTES, 'UTF-8' );
	}

	/**
     * Get the current PHP runtime version as major.minor (e.g., 8.3).
     *
     * @return string Runtime PHP version string.
     */
 	private static function get_runtime_major_minor(): string {
		$ver = PHP_VERSION; // e.g., 8.3.6
		if ( preg_match( '/^(\d+)\.(\d+)/', $ver, $m ) ) {
			return $m[1] . '.' . $m[2];
		}
		return $ver;
	}

	/**
     * Get the list of selectable target PHP versions (major.minor).
     *
     * @return array<string> Target versions supported by the scanner.
     */
 	private static function get_available_targets(): array {
		return [ '8.0', '8.1', '8.2', '8.3', '8.4' ];
	}

	/**
	 * Parse and sanitize request input (e.g., from $_POST).
	 *
	 * @param array $src Source array of request variables.
	 * @return array{
	 *   target:string,
	 *   include_warnings:bool,
	 *   scan_all:bool,
	 *   plugins:array,
	 *   extra_excludes:array,
	 *   extra_excludes_raw:string
	 * }
	 */
	private static function parse_request( array $src ): array {
		$selected_target    = isset( $src['pcd_target'] ) ? preg_replace( '/[^0-9\.]+/', '', (string) wp_unslash( $src['pcd_target'] ) ) : '';
		$include_warnings   = ! empty( $src['pcd_include_warnings'] );
		$scan_all           = ! empty( $src['pcd_scan_all'] );
		$sel_plugins        = ( isset( $src['pcd_plugins'] ) && is_array( $src['pcd_plugins'] ) ) ? array_map( 'sanitize_text_field', wp_unslash( $src['pcd_plugins'] ) ) : [];
		$extra_excludes_raw = isset( $src['pcd_extra_excludes'] ) ? (string) wp_unslash( $src['pcd_extra_excludes'] ) : '';
		$extra_excludes     = array_filter( array_map( 'trim', explode( ',', $extra_excludes_raw ) ) );

		return [
			'target'             => (string) $selected_target,
			'include_warnings'   => $include_warnings,
			'scan_all'           => $scan_all,
			'plugins'            => $sel_plugins,
			'extra_excludes'     => $extra_excludes,
			'extra_excludes_raw' => $extra_excludes_raw,
		];
	}

	/**
     * List plugin directory slugs in WP_PLUGIN_DIR.
     *
     * @return array<string> Plugin directory names.
     */
	private static function list_plugins(): array {
		$base = WP_PLUGIN_DIR;
		$dirs = scandir( $base );
		if ( false === $dirs || ! is_array( $dirs ) ) {
			return [];
		}
		$plugins = [];
		foreach ( $dirs as $d ) {
			if ( '.' === $d || '..' === $d ) {
				continue;
			}
			$path = $base . '/' . $d;
			if ( is_dir( $path ) ) {
				$plugins[] = $d;
			}
		}
		sort( $plugins );
		return $plugins;
	}

	/**
     * Find the phpcs executable path.
     *
     * Prefer the plugin-local vendor/bin first, falling back to project root vendor/bin.
     *
     * @return string Absolute path to phpcs (may not exist).
     */
 	private static function find_phpcs_binary(): string {
		// Prefer plugin-local vendor first (after composer install), then root vendor.
		$local = plugin_dir_path( __FILE__ ) . 'vendor/bin/phpcs';
		if ( file_exists( $local ) && is_executable( $local ) ) {
			return $local; }
		$root = ABSPATH . 'vendor/bin/phpcs';
		return $root;
	}

	/**
     * Build the phpcs command line for a given target version and input paths.
     *
     * @param string $php_minor        Target PHP version (major.minor).
     * @param bool   $include_warnings Whether to include warnings in results.
     * @param array  $targets          Paths to scan.
     * @param array  $extra_excludes   Extra sniff codes to exclude.
     * @return array<int,string> Command parts.
     */
 	private static function build_phpcs_cmd( string $php_minor, bool $include_warnings, array $targets, array $extra_excludes ): array {
		$bin    = self::find_phpcs_binary();
		$ignore = '*/tests/*,*/Tests/*,*/test/*,*/Test/*,*/__tests__/*,*/spec/*,*/Spec/*,*/examples/*,*/example/*,*/Fixtures/*,*/fixtures/*,*/vendor/*/tests/*,*/vendor/*/*Tests/*,*/vendor_prefixed/*/Tests/*,*/vendor-scoped/*/Tests/*,*/third-party/*/Tests/*';
		$args   = [
			escapeshellarg( $bin ),
			'--report=json',
			'--standard=PHPCompatibilityWP',
			'--extensions=php',
			'--runtime-set',
			'testVersion',
			escapeshellarg( $php_minor . '-' . $php_minor ),
			'--ignore=' . escapeshellarg( $ignore ),
		];
		if ( ! empty( $extra_excludes ) ) {
			$args[] = '--exclude=' . escapeshellarg( implode( ',', array_unique( array_filter( $extra_excludes ) ) ) );
		}
		if ( ! $include_warnings ) {
			$args[] = '--warning-severity=0';
		}
		foreach ( $targets as $t ) {
			$args[] = escapeshellarg( $t ); }
		return $args;
	}

	/**
     * Run a shell command assembling stdout, stderr and exit code.
     *
     * Uses proc_open when available; falls back to exec() if proc_open is
     * disabled in the PHP configuration. Falls back captures combined output.
     *
     * @param array<int,string> $cmd_parts Command parts to be imploded with spaces.
     * @return array{0:int,1:string,2:string,3:string} [exitCode, stdout, stderr, fullCmd]
     */
	private static function run_cmd( array $cmd_parts ): array {
		$cmd  = implode( ' ', $cmd_parts );
		$out  = '';
		$err  = '';
		$code = 1;

		$disabled       = ini_get( 'disable_functions' );
		$disabled_list  = is_string( $disabled ) && '' !== $disabled ? array_map( 'trim', explode( ',', $disabled ) ) : [];
		$proc_available = function_exists( 'proc_open' ) && ! in_array( 'proc_open', $disabled_list, true );

		if ( $proc_available ) {
			$descriptor = [
				1 => [ 'pipe', 'w' ],
				2 => [ 'pipe', 'w' ],
			];
			$proc       = proc_open( $cmd, $descriptor, $pipes, ABSPATH ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open
			if ( is_resource( $proc ) ) {
				$out = stream_get_contents( $pipes[1] );
				$err = stream_get_contents( $pipes[2] );
				foreach ( $pipes as $p ) {
					if ( is_resource( $p ) ) {
						// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
						fclose( $p );
					}
				}
				$code = proc_close( $proc );
			}
		} else {
			$exec_available = function_exists( 'exec' ) && ! in_array( 'exec', $disabled_list, true );
			if ( $exec_available ) {
				$lines = [];
				// Capture both stdout and stderr to lines.
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
				exec( $cmd . ' 2>&1', $lines, $code );
				$out = implode( "\n", $lines );
			} else {
				$err = 'Unable to run command: both proc_open() and exec() are disabled on this server.';
			}
		}

		return [ $code, $out, $err, $cmd ];
	}

	/**
     * Run a PHPCompatibility scan via phpcs for the given plugins/paths.
     *
     * @param string $php_minor        Target PHP version (major.minor).
     * @param bool   $include_warnings Whether to include warnings in results.
     * @param array  $plugin_slugs     Plugin slugs to scan.
     * @param array  $extra_excludes   Extra sniff codes to exclude.
     * @return array{0:int,1:string,2:string,3:string} Process result [code, stdout, stderr, cmd].
     */
 	private static function phpcs_scan( string $php_minor, bool $include_warnings, array $plugin_slugs, array $extra_excludes ): array {
		$paths = [];
		foreach ( $plugin_slugs as $slug ) {
			$paths[] = WP_PLUGIN_DIR . '/' . $slug; }
		if ( empty( $paths ) ) {
			$paths[] = WP_PLUGIN_DIR; }
		return self::run_cmd( self::build_phpcs_cmd( $php_minor, $include_warnings, $paths, $extra_excludes ) );
	}

	/**
     * Flatten the PHPCS JSON report into a list of message arrays.
     *
     * @param array $report Decoded PHPCS JSON report.
     * @return array<int,array<string,mixed>> Messages with file path injected.
     */
 	private static function to_messages( array $report ): array {
		$files = isset( $report['files'] ) && is_array( $report['files'] ) ? $report['files'] : [];
		$out   = [];
		foreach ( $files as $path => $info ) {
			$messages = isset( $info['messages'] ) && is_array( $info['messages'] ) ? $info['messages'] : [];
			foreach ( $messages as $m ) {
				if ( ! isset( $m['type'] ) ) {
					continue; }
				if ( 'ERROR' !== $m['type'] && 'WARNING' !== $m['type'] ) {
					continue; }
				$out[] = $m + [ 'path' => $path ];
			}
		}
		return $out;
	}

	/**
     * Build a unique key for a message combining file path, source, and message.
     *
     * @param array $m Message array from PHPCS.
     * @return string Unique key string.
     */
 	private static function msg_key( array $m ): string {
		$path    = isset( $m['path'] ) ? (string) $m['path'] : '';
		$source  = isset( $m['source'] ) ? (string) $m['source'] : '';
		$message = isset( $m['message'] ) ? (string) $m['message'] : '';
		return $path . '|' . $source . '|' . $message;
	}

	/**
     * Compute messages which are new in the target report compared to the base.
     *
     * @param array $base   Decoded PHPCS report for baseline.
     * @param array $target Decoded PHPCS report for target.
     * @return array<int,array<string,mixed>> New messages in target only.
     */
 	private static function compute_delta( array $base, array $target ): array {
		$base_msgs   = self::to_messages( $base );
		$target_msgs = self::to_messages( $target );
		$base_keys   = [];
		foreach ( $base_msgs as $m ) {
			$base_keys[ self::msg_key( $m ) ] = true; }
		$delta = [];
		foreach ( $target_msgs as $m ) {
			$k = self::msg_key( $m );
			if ( ! isset( $base_keys[ $k ] ) ) {
				$delta[] = $m; }
		}
		return $delta;
	}

	/**
     * Extract the plugin slug from an absolute file path inside wp-content/plugins.
     *
     * @param string $path Absolute file path.
     * @return string Plugin slug or 'unknown'.
     */
 	private static function plugin_slug_from_path( string $path ): string {
		$base = str_replace( '\\', '/', trailingslashit( WP_PLUGIN_DIR ) );
		$norm = str_replace( '\\', '/', $path );
		if ( 0 === strpos( $norm, $base ) ) {
			$rel   = substr( $norm, strlen( $base ) );
			$parts = explode( '/', $rel );
			return $parts[0] ?? 'unknown';
		}
		return 'unknown';
	}

	/**
     * Group messages by plugin slug.
     *
     * @param array<int,array<string,mixed>> $messages Messages list.
     * @return array<string,array<int,array<string,mixed>>> Grouped by slug.
     */
 	private static function group_by_plugin( array $messages ): array {
		$groups = [];
		foreach ( $messages as $m ) {
			$slug = self::plugin_slug_from_path( (string) $m['path'] );
			if ( ! isset( $groups[ $slug ] ) ) {
				$groups[ $slug ] = []; }
			$groups[ $slug ][] = $m;
		}
		ksort( $groups );
		return $groups;
	}

	/**
	 * Legacy inline CSS output (now replaced by enqueued assets).
	 *
	 * Kept for backward compatibility; does nothing now.
	 */
	public static function admin_head_css(): void {
		// No-op. Styles are enqueued via enqueue_assets().
	}

	/**
	 * Conditionally enqueue admin scripts and styles for this plugin.
	 *
	 * - Enqueue CSS on the Tools page and Plugins list (for badges).
	 * - Enqueue JS only on the Tools page.
	 */
	public static function enqueue_assets(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$hook   = $screen ? $screen->id : '';

		$assets_base_url  = plugin_dir_url( __FILE__ ) . 'assets/';
		$assets_base_path = plugin_dir_path( __FILE__ ) . 'assets/';

		$css_rel  = 'css/pcd-admin.css';
		$js_rel   = 'js/pcd-admin.js';
		$css_file = $assets_base_path . $css_rel;
		$js_file  = $assets_base_path . $js_rel;
		$css_ver  = file_exists( $css_file ) ? (string) filemtime( $css_file ) : '1';
		$js_ver   = file_exists( $js_file ) ? (string) filemtime( $js_file ) : '1';

		// Enqueue CSS on the Tools page and Plugins screens.
		if ( 'tools_page_php-compat-delta' === $hook || 'plugins' === $hook || 'plugins-network' === $hook ) {
			wp_enqueue_style( 'pcd-admin', $assets_base_url . $css_rel, [], $css_ver );
		}

		// Enqueue JS only on the Tools page.
		if ( 'tools_page_php-compat-delta' === $hook ) {
			wp_enqueue_script( 'pcd-admin', $assets_base_url . $js_rel, [ 'jquery' ], $js_ver, true );
		}
	}

	/**
     * Add the latest scan result badge next to each plugin on the Plugins screen.
     *
     * @param array  $meta Existing row meta.
     * @param string $file Plugin file path.
     * @return array Modified row meta with badge (if available).
     */
 	public static function plugin_row_meta_note( array $meta, string $file ): array {
		$opt = get_option( self::OPT_LAST_SCAN );
		if ( ! is_array( $opt ) || empty( $opt['results'] ) ) {
			return $meta; }
		$slug = dirname( plugin_basename( $file ) );
		if ( isset( $opt['results'][ $slug ] ) ) {
			$info    = $opt['results'][ $slug ];
			$runtime = isset( $opt['runtime'] ) ? (string) $opt['runtime'] : '';
			$target  = isset( $opt['target'] ) ? (string) $opt['target'] : '';
			$issues  = isset( $info['issues'] ) ? (int) $info['issues'] : 0;
			$cls     = 0 < $issues ? 'pcd-badge pcd-badge--bad' : 'pcd-badge pcd-badge--ok';
			$txt     = 0 < $issues
				? ( 'PHP ' . $runtime . '→' . $target . ': ' . $issues . ' new issues' )
				: ( 'PHP ' . $runtime . '→' . $target . ': OK' );
			$meta[]  = '<span class="' . self::h( $cls ) . '">' . self::h( $txt ) . '</span>';
		}
		return $meta;
	}

	/**
     * Render the Tools page with AJAX-enabled form for running scans.
     */
	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' ); }
		$runtime     = self::get_runtime_major_minor();
		$targets     = self::get_available_targets();
		$all_plugins = self::list_plugins();

		// Verify nonce before processing any input.
        $nonce_ok = isset( $_POST['pcd_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( (string) $_POST['pcd_nonce'] ) ), 'pcd' );

		// Defaults.
		$selected_target    = '';
		$include_warnings   = false;
		$scan_all           = false;
		$sel_plugins        = [];
		$extra_excludes     = [];
		$extra_excludes_raw = '';

		if ( $nonce_ok ) {
			$parsed = self::parse_request( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce already verified above.
			[
				'target'             => $selected_target,
				'include_warnings'   => $include_warnings,
				'scan_all'           => $scan_all,
				'plugins'            => $sel_plugins,
				'extra_excludes'     => $extra_excludes,
				'extra_excludes_raw' => $extra_excludes_raw,
			]       = $parsed;
		}

		// Filter target dropdown to strictly greater than runtime only.
		$targets_filtered = array_values(
			array_filter(
				$targets,
				static function ( $t ) use ( $runtime ) {
					return version_compare( (string) $t, $runtime, '>' );
				}
			)
		);

		echo '<div class="wrap pcd-wrap">';
		echo '<h1>PHP Compatibility Delta</h1>';
		echo '<p class="pcd-meta">Baseline: <code>' . esc_html( $runtime ) . '</code> (current runtime). Choose one target to compare against.</p>';

		echo '<form id="pcd-form" method="post">';
		wp_nonce_field( 'pcd', 'pcd_nonce' );
		echo '<table class="form-table"><tbody>';
		echo '<tr><th><label for="pcd_target">Target PHP</label></th><td><select id="pcd_target" name="pcd_target">';
		foreach ( $targets_filtered as $t ) {
			echo '<option value="' . esc_attr( (string) $t ) . '"' . selected( (string) $t, $selected_target, false ) . '>' . esc_html( (string) $t ) . '</option>';
		}
		echo '</select></td></tr>';

		echo '<tr><th><label for="pcd_include_warnings">Include warnings</label></th><td><label><input type="checkbox" id="pcd_include_warnings" name="pcd_include_warnings" value="1"' . checked( (bool) $include_warnings, true, false ) . '> Include warnings</label></td></tr>';

		echo '<tr><th>Plugins</th><td>';
		echo '<label><input type="checkbox" name="pcd_scan_all" value="1"' . checked( $scan_all, true, false ) . '> Scan all plugins</label>';
		echo '<p><em>Or select specific plugins:</em></p>';
		echo '<div class="pcd-plugin-list">';
		foreach ( $all_plugins as $slug ) {
			$is_checked = in_array( $slug, $sel_plugins, true );
			echo '<label style="display:block"><input type="checkbox" name="pcd_plugins[]" value="' . esc_attr( $slug ) . '"' . checked( (bool) $is_checked, true, false ) . '> ' . esc_html( (string) $slug ) . '</label>';
		}
		echo '</div>';
		echo '</td></tr>';

		echo '<tr><th><label for="pcd_extra_excludes">Extra excludes</label></th><td><input type="text" id="pcd_extra_excludes" name="pcd_extra_excludes" value="' . esc_attr( (string) $extra_excludes_raw ) . '" class="regular-text"> <span class="description">Comma-separated sniff codes to exclude if a scan fails.</span></td></tr>';
		echo '</tbody></table>';
		echo '<p><button type="submit" class="button button-primary">Run scan</button></p>';
		echo '</form>';

		// Results container for AJAX responses.
		echo '<div id="pcd-results"></div>';

		// Non-AJAX fallback when directly posting the form (e.g., if JS disabled).
		if ( $nonce_ok && '' !== $selected_target ) {
			if ( version_compare( $selected_target, $runtime, '<=' ) ) {
				echo '<div class="notice notice-error"><p>Target PHP must be greater than runtime PHP ' . esc_html( $runtime ) . '.</p></div>';
				echo '</div>';
				return;
			}
			$plugins = $scan_all ? $all_plugins : $sel_plugins;
			if ( empty( $plugins ) ) {
				echo '<div class="notice notice-warning"><p>No plugins selected. Please choose plugins or enable "Scan all plugins".</p></div>';
				echo '</div>';
				return;
			}
			$html = self::generate_results_html( $runtime, $selected_target, $include_warnings, $plugins, $extra_excludes );
			echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML already escaped within generator.
		}

		echo '</div>';
	}
	/**
	 * Generate the HTML for scan results, including notices and tables.
	 *
	 * Runs baseline and target scans, computes the delta, persists a summary for
	 * plugin list badges, and returns the HTML string (already escaped within).
	 *
	 * @param string $runtime          Runtime PHP version (major.minor).
	 * @param string $selected_target  Target PHP version (major.minor).
	 * @param bool   $include_warnings Whether to include warnings.
	 * @param array  $plugins          Plugin slugs to scan.
	 * @param array  $extra_excludes   Extra sniff codes to exclude.
	 * @return string HTML markup for the results.
	 */
	private static function generate_results_html( string $runtime, string $selected_target, bool $include_warnings, array $plugins, array $extra_excludes ): string {
		$html = '';

		// Baseline scan.
		list( $code1, $json1, $err1, $cmd1 ) = self::phpcs_scan( $runtime, $include_warnings, $plugins, $extra_excludes );
		if ( 0 !== $code1 ) {
			$html .= '<div class="notice notice-error"><p>Baseline scan failed (PHP ' . self::h( $runtime ) . ').</p>';
			$html .= '<p><strong>Command:</strong> <code>' . self::h( $cmd1 ) . '</code></p>';
			$html .= '<pre style="white-space:pre-wrap">' . self::h( $err1 ? $err1 : $json1 ) . '</pre>';
			$html .= '<p>Try adding the failing sniff(s) to Extra excludes above and rerun.</p></div>';
			return $html;
		}
		$report1 = json_decode( $json1, true );
		if ( ! is_array( $report1 ) ) {
			return '<div class="notice notice-error"><p>Could not parse baseline JSON output.</p></div>';
		}

		// Target scan.
		list( $code2, $json2, $err2, $cmd2 ) = self::phpcs_scan( $selected_target, $include_warnings, $plugins, $extra_excludes );
		if ( 0 !== $code2 ) {
			$html .= '<div class="notice notice-error"><p>Target scan failed (PHP ' . self::h( $selected_target ) . ').</p>';
			$html .= '<p><strong>Command:</strong> <code>' . self::h( $cmd2 ) . '</code></p>';
			$html .= '<pre style="white-space:pre-wrap">' . self::h( $err2 ? $err2 : $json2 ) . '</pre>';
			$html .= '<p>Try adding the failing sniff(s) to Extra excludes above and rerun.</p></div>';
			return $html;
		}
		$report2 = json_decode( $json2, true );
		if ( ! is_array( $report2 ) ) {
			return '<div class="notice notice-error"><p>Could not parse target JSON output.</p></div>';
		}

		$delta  = self::compute_delta( $report1, $report2 );
		$groups = self::group_by_plugin( $delta );

		// Persist results for plugin list badges.
		$results = [];
		foreach ( $plugins as $slug ) {
			$results[ $slug ] = [ 'issues' => isset( $groups[ $slug ] ) ? count( $groups[ $slug ] ) : 0 ];
		}
		update_option(
			self::OPT_LAST_SCAN,
			[
				'runtime' => $runtime,
				'target'  => $selected_target,
				'results' => $results,
			],
			false
		);

		$html .= '<hr />';
		$html .= '<h2>Results: Baseline ' . self::h( $runtime ) . ' → Target ' . self::h( $selected_target ) . '</h2>';

		if ( empty( $groups ) ) {
			$html .= '<div class="notice notice-success"><p>All selected plugins show no new issues for PHP ' . self::h( $selected_target ) . ' compared to ' . self::h( $runtime ) . '. Compatible.</p></div>';
			return $html;
		}

		// Incompatible plugins with details.
		foreach ( $groups as $slug => $msgs ) {
			$count = count( $msgs );
			$html .= '<h3 id="plugin-' . self::h( $slug ) . '">' . self::h( $slug ) . '</h3>';
			$html .= '<p class="pcd-summary--bad">Not compatible with PHP ' . self::h( $selected_target ) . ' (new issues: ' . (int) $count . '). Consider contacting the developer or finding a replacement.</p>';
			$html .= '<table class="widefat fixed striped"><thead><tr><th>File</th><th>Line</th><th>Col</th><th>Type</th><th>Message</th><th>Source</th></tr></thead><tbody>';
			foreach ( $msgs as $m ) {
				$file  = isset( $m['path'] ) ? (string) $m['path'] : '';
				$line  = isset( $m['line'] ) ? (int) $m['line'] : 0;
				$col   = isset( $m['column'] ) ? (int) $m['column'] : 0;
				$type  = isset( $m['type'] ) ? (string) $m['type'] : '';
				$msg   = isset( $m['message'] ) ? (string) $m['message'] : '';
				$src   = isset( $m['source'] ) ? (string) $m['source'] : '';
				$html .= '<tr class="' . self::h( $type ) . '"><td>' . self::h( preg_replace( '#^.*/wp-content/plugins/#', '', $file ) ) . '</td><td>' . (int) $line . '</td><td>' . (int) $col . '</td><td><strong>' . self::h( $type ) . '</strong></td><td>' . self::h( $msg ) . '</td><td><code>' . self::h( $src ) . '</code></td></tr>';
			}
			$html .= '</tbody></table>';
		}

		// Compatible plugins list.
		$incompatible = array_keys( $groups );
		$compatible   = array_values( array_diff( $plugins, $incompatible ) );
		if ( ! empty( $compatible ) ) {
			$html .= '<h2>Compatible plugins</h2><ul class="ul-disc">';
			foreach ( $compatible as $slug ) {
				$html .= '<li><strong>' . self::h( $slug ) . '</strong>: <span class="pcd-summary--ok">Compatible with PHP ' . self::h( $selected_target ) . ' (no new issues)</span></li>';
			}
			$html .= '</ul>';
		}

		return $html;
	}

	/**
	 * AJAX handler for running scans without page reload.
	 */
	public static function ajax_scan(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'Insufficient permissions.' ] );
		}
		check_ajax_referer( 'pcd', 'pcd_nonce' );

		$runtime     = self::get_runtime_major_minor();
		$all_plugins = self::list_plugins();

		$parsed = self::parse_request( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified via check_ajax_referer.
		[
			'target'           => $selected_target,
			'include_warnings' => $include_warnings,
			'scan_all'         => $scan_all,
			'plugins'          => $sel_plugins,
			'extra_excludes'   => $extra_excludes,
		]       = $parsed;

		if ( version_compare( (string) $selected_target, (string) $runtime, '<=' ) ) {
			wp_send_json_error( [ 'message' => 'Target PHP must be greater than runtime PHP ' . self::h( $runtime ) . '.' ] );
		}

		$plugins = $scan_all ? $all_plugins : $sel_plugins;
		if ( empty( $plugins ) ) {
			wp_send_json_error( [ 'message' => 'No plugins selected. Please choose plugins or enable "Scan all plugins".' ] );
		}

		$html = self::generate_results_html( $runtime, $selected_target, (bool) $include_warnings, (array) $plugins, (array) $extra_excludes );
		wp_send_json_success( [ 'html' => $html ] );
	}
}

PCD_Plugin::init();
