<?php
/**
 * Plugin Name: PHP Compatibility Scanner
 * Author URI: https://digital.brightleaf.info/
 * Description: Scan WordPress plugins for PHP compatibility issues between current PHP and newer versions. Shows inline results and stores scan summaries.
 * Version: 1.0.0
 * Author: BrightLeaf Digital
 * License: GPL-2.0+
 * Requires PHP: 7.4
 */

use PHP_CodeSniffer\Runner;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main plugin class for PHP Compatibility Scanner.
 *
 * Provides an admin Tools page to scan installed plugins for new PHPCompatibility
 * issues between the current runtime PHP version and a chosen target PHP version.
 * Also stores a summary next to each plugin on the plugins list page.
 */
class BrightLeaf_Digital_Php_Checker_Plugin {
	const OPT_LAST_SCAN        = 'brightleaf_digital_php_checker_last_scan_results';
	const TRANSIENT_PREFIX     = 'brightleaf_digital_php_checker_job_';
	const JOB_TTL              = 21600; // 6 hours
	const PER_PLUGIN_MSG_LIMIT = 300; // cap stored messages per plugin for stability

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
		add_action( 'wp_ajax_brightleaf_digital_php_checker_scan', [ __CLASS__, 'ajax_scan' ] );
		// Async job endpoints and cron runner.
		add_action( 'wp_ajax_brightleaf_digital_php_checker_scan_start', [ __CLASS__, 'ajax_scan_start' ] );
		add_action( 'wp_ajax_brightleaf_digital_php_checker_scan_status', [ __CLASS__, 'ajax_scan_status' ] );
		add_action( 'wp_ajax_brightleaf_digital_php_checker_scan_cancel', [ __CLASS__, 'ajax_scan_cancel' ] );
		add_action( 'wp_ajax_brightleaf_digital_php_checker_scan_toggle_pause', [ __CLASS__, 'ajax_scan_toggle_pause' ] );
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
     * Register the Tools page under Tools > PHP Compatibility Scanner.
     *
     * Checks user capability before registering the page.
     */
 	public static function register_tools_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		add_management_page(
			'PHP Compatibility Scanner',
			'PHP Compatibility Scanner',
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
		$selected_target    = isset( $src['brightleaf_digital_php_checker_target'] ) ? preg_replace( '/[^0-9\.]+/', '', (string) wp_unslash( $src['brightleaf_digital_php_checker_target'] ) ) : '';
		$include_warnings   = ! empty( $src['brightleaf_digital_php_checker_include_warnings'] );
		$scan_all_plugins   = ! empty( $src['brightleaf_digital_php_checker_scan_all'] );
		$sel_plugins        = ( isset( $src['brightleaf_digital_php_checker_plugins'] ) && is_array( $src['brightleaf_digital_php_checker_plugins'] ) ) ? array_map( 'sanitize_text_field', wp_unslash( $src['brightleaf_digital_php_checker_plugins'] ) ) : [];
		$themes_all         = ! empty( $src['brightleaf_digital_php_checker_themes_all'] );
		$sel_themes         = ( isset( $src['brightleaf_digital_php_checker_themes'] ) && is_array( $src['brightleaf_digital_php_checker_themes'] ) ) ? array_map( 'sanitize_text_field', wp_unslash( $src['brightleaf_digital_php_checker_themes'] ) ) : [];
		$scan_parent_child  = ! empty( $src['brightleaf_digital_php_checker_scan_parent_child'] );
		$extra_excludes_raw = isset( $src['brightleaf_digital_php_checker_extra_excludes'] ) ? (string) wp_unslash( $src['brightleaf_digital_php_checker_extra_excludes'] ) : '';
		$extra_excludes     = array_filter( array_map( 'trim', explode( ',', $extra_excludes_raw ) ) );

		return [
			'target'             => (string) $selected_target,
			'include_warnings'   => $include_warnings,
			'scan_all'           => $scan_all_plugins,
			'plugins'            => $sel_plugins,
			'themes_all'         => $themes_all,
			'themes'             => $sel_themes,
			'scan_parent_child'  => $scan_parent_child,
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
        return ABSPATH . 'vendor/bin/phpcs';
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
     * Uses exec() only. If exec() is disabled, returns an error and callers should
     * fall back to the embedded runner.
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
		$exec_available = function_exists( 'exec' ) && ! in_array( 'exec', $disabled_list, true );

		if ( $exec_available ) {
			$lines = [];
			// Capture both stdout and stderr to lines.
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
			exec( $cmd . ' 2>&1', $lines, $code );
			$out = implode( "\n", $lines );
		} else {
			$err = 'Unable to run command: exec() is disabled on this server.';
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
		return self::phpcs_scan_paths( $php_minor, $include_warnings, $paths, $extra_excludes );
	}

	/**
	 * Run a PHPCompatibility scan via phpcs for arbitrary filesystem paths.
	 * Prefer CLI if available; fall back to embedded runner.
	 *
	 * @param string $php_minor        Target PHP version (major.minor).
	 * @param bool   $include_warnings Whether to include warnings.
	 * @param array  $paths            Absolute paths to scan.
	 * @param array  $extra_excludes   Extra sniff codes to exclude.
	 * @return array{0:int,1:string,2:string,3:string}
	 */
	private static function phpcs_scan_paths( string $php_minor, bool $include_warnings, array $paths, array $extra_excludes ): array {
		if ( self::cli_available() ) {
			return self::run_cmd( self::build_phpcs_cmd( $php_minor, $include_warnings, $paths, $extra_excludes ) );
		}
		return self::run_phpcs_embedded( $php_minor, $include_warnings, $paths, $extra_excludes );
	}

	/**
	 * Determine if CLI execution is available and phpcs binary exists.
	 *
	 * @return bool
	 */
	private static function cli_available(): bool {
		$bin = self::find_phpcs_binary();
		if ( ! file_exists( $bin ) ) {
			return false;
		}
		$disabled      = ini_get( 'disable_functions' );
		$disabled_list = is_string( $disabled ) && '' !== $disabled ? array_map( 'trim', explode( ',', $disabled ) ) : [];
		$exec_ok       = function_exists( 'exec' ) && ! in_array( 'exec', $disabled_list, true );
		return $exec_ok;
	}

	/**
	 * Embedded PHPCS runner without shell access.
	 *
	 * @param string $php_minor        Target PHP version (major.minor).
	 * @param bool   $include_warnings Include warnings.
	 * @param array  $paths            Paths to scan.
	 * @param array  $extra_excludes   Extra excludes.
	 * @return array{0:int,1:string,2:string,3:string}
	 */
	private static function run_phpcs_embedded( string $php_minor, bool $include_warnings, array $paths, array $extra_excludes ): array {
		$json = '';
		$err  = '';
		$cmd  = 'embedded-phpcs';
		try {
			$report_file = wp_tempnam( 'phpcs-report' );
			if ( ! $report_file ) {
				return [ 1, '', 'Failed to create temp file for report.', $cmd ];
			}
			$args = [
				'--report=json',
				'--report-file=' . $report_file,
				'--standard=PHPCompatibilityWP',
				'--extensions=php',
				'--runtime-set',
				'testVersion',
				$php_minor . '-' . $php_minor,
			];
			if ( ! $include_warnings ) {
				$args[] = '--warning-severity=0';
			}
			if ( ! empty( $extra_excludes ) ) {
				$args[] = '--exclude=' . implode( ',', array_unique( array_filter( $extra_excludes ) ) );
			}
			foreach ( $paths as $p ) {
				$args[] = $p;
			}
			// Use PHPCS Runner with injected CLI args via $argv to avoid shell.
			$argv_backup     = $GLOBALS['argv'] ?? null;
			$_argv_backup    = isset( $_SERVER['argv'] ) ? sanitize_text_field( wp_unslash( $_SERVER['argv'] ) ) : null;
			$argv            = array_merge( [ 'phpcs' ], $args );
			$GLOBALS['argv'] = $argv;
			$_SERVER['argv'] = $argv;
			$runner          = new Runner();
			$runner->runPHPCS();
			// Restore argv globals.
			if ( null !== $argv_backup ) {
				$GLOBALS['argv'] = $argv_backup;
			} else {
				unset( $GLOBALS['argv'] ); }
			if ( null !== $_argv_backup ) {
				$_SERVER['argv'] = $_argv_backup;
			} else {
				unset( $_SERVER['argv'] ); }
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading local temp file, not remote URL
			$json = is_readable( $report_file ) ? (string) file_get_contents( $report_file ) : '';
			$code = 0;
		} catch ( Throwable $e ) {
			$err  = $e->getMessage();
			$code = 1;
		}
		return [ $code, $json, $err, $cmd ];
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
		if ( str_starts_with( $norm, $base ) ) {
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

		$css_rel  = 'css/brightleaf-digital-php-checker-admin.css';
		$js_rel   = 'js/brightleaf-digital-php-checker-admin.js';
		$css_file = $assets_base_path . $css_rel;
		$js_file  = $assets_base_path . $js_rel;
		$css_ver  = file_exists( $css_file ) ? (string) filemtime( $css_file ) : '1';
		$js_ver   = file_exists( $js_file ) ? (string) filemtime( $js_file ) : '1';

		// Enqueue CSS on the Tools page and Plugins screens.
		if ( 'tools_page_php-compat-delta' === $hook || 'plugins' === $hook || 'plugins-network' === $hook ) {
			wp_enqueue_style( 'brightleaf-digital-php-checker-admin', $assets_base_url . $css_rel, [], $css_ver );
		}

		// Enqueue JS only on the Tools page.
		if ( 'tools_page_php-compat-delta' === $hook ) {
			wp_enqueue_script( 'brightleaf-digital-php-checker-admin', $assets_base_url . $js_rel, [ 'jquery' ], $js_ver, true );
			// Provide polling configuration.
			wp_localize_script(
                'brightleaf-digital-php-checker-admin',
                'brightleaf_digital_php_checker_Ajax',
                [
					'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
					'pollInterval' => 1000,
				]
                );
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
			$cls     = 0 < $issues ? 'brightleaf-digital-php-checker-badge brightleaf-digital-php-checker-badge--bad' : 'brightleaf-digital-php-checker-badge brightleaf-digital-php-checker-badge--ok';
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
		$all_themes  = function_exists( 'wp_get_themes' ) ? wp_get_themes() : [];

		// Verify nonce before processing any input.
      		$nonce_ok = isset( $_POST['brightleaf_digital_php_checker_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( (string) $_POST['brightleaf_digital_php_checker_nonce'] ) ), 'brightleaf_digital_php_checker' );

		// Defaults.
		$selected_target    = '';
		$include_warnings   = false;
		$scan_all           = false;
		$sel_plugins        = [];
		$themes_all         = false;
		$sel_themes         = [];
		$scan_parent_child  = true; // Option enabled by default.
		$extra_excludes     = [];
		$extra_excludes_raw = '';

		if ( $nonce_ok ) {
			$parsed = self::parse_request( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce already verified above.
			[
				'target'             => $selected_target,
				'include_warnings'   => $include_warnings,
				'scan_all'           => $scan_all,
				'plugins'            => $sel_plugins,
				'themes_all'         => $themes_all,
				'themes'             => $sel_themes,
				'scan_parent_child'  => $scan_parent_child,
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

		echo '<div class="wrap brightleaf-digital-php-checker-wrap">';
		echo '<h1>PHP Compatibility Scanner</h1>';
		echo '<p class="brightleaf-digital-php-checker-meta">Baseline: <code>' . esc_html( $runtime ) . '</code> (current runtime). Choose one target to compare against.</p>';

		echo '<form id="brightleaf-digital-php-checker-form" method="post">';
		wp_nonce_field( 'brightleaf_digital_php_checker', 'brightleaf_digital_php_checker_nonce' );
		echo '<table class="form-table"><tbody>';
		echo '<tr><th><label for="brightleaf-digital-php-checker-target">Target PHP</label></th><td><select id="brightleaf-digital-php-checker-target" name="brightleaf_digital_php_checker_target">';
		foreach ( $targets_filtered as $t ) {
			echo '<option value="' . esc_attr( (string) $t ) . '"' . selected( (string) $t, $selected_target, false ) . '>' . esc_html( (string) $t ) . '</option>';
		}
		echo '</select></td></tr>';

		echo '<tr><th><label for="brightleaf-digital-php-checker-include-warnings">Include warnings</label></th><td><label><input type="checkbox" id="brightleaf-digital-php-checker-include-warnings" name="brightleaf_digital_php_checker_include_warnings" value="1"' . checked( $include_warnings, true, false ) . '> Include warnings</label></td></tr>';

		echo '<tr><th>Plugins</th><td>';
		echo '<label><input type="checkbox" name="brightleaf_digital_php_checker_scan_all" value="1"' . checked( $scan_all, true, false ) . '> Scan all plugins</label>';
		echo '<p><em>Or select specific plugins:</em></p>';
		echo '<div class="brightleaf-digital-php-checker-plugin-list">';
		foreach ( $all_plugins as $slug ) {
			$is_checked = in_array( $slug, $sel_plugins, true );
			echo '<label style="display:block"><input type="checkbox" name="brightleaf_digital_php_checker_plugins[]" value="' . esc_attr( $slug ) . '"' . checked( $is_checked, true, false ) . '> ' . esc_html( $slug ) . '</label>';
		}
		echo '</div>';
		echo '</td></tr>';

		// Themes section.
		echo '<tr><th>Themes</th><td>';
		echo '<label><input type="checkbox" name="brightleaf_digital_php_checker_themes_all" value="1"' . checked( $themes_all, true, false ) . '> Scan all themes</label>';
		echo '<p><em>Or select specific themes:</em></p>';
		echo '<div class="brightleaf-digital-php-checker-plugin-list">';
		if ( is_array( $all_themes ) && ! empty( $all_themes ) ) {
			$active_theme      = wp_get_theme();
			$active_stylesheet = $active_theme->get_stylesheet();
			foreach ( $all_themes as $stylesheet => $theme_obj ) {
				$name        = is_object( $theme_obj ) ? (string) $theme_obj->get( 'Name' ) : (string) $stylesheet;
				$parent      = is_object( $theme_obj ) ? (string) $theme_obj->get( 'Template' ) : '';
				$is_active   = ( $stylesheet === $active_stylesheet );
				$label_extra = '';
				if ( $is_active ) {
					$label_extra .= ' <em>(active theme)</em>';
				}
				if ( $parent ) {
					$label_extra .= ' <em>(child of ' . esc_html( $parent ) . ')</em>';
				}
				$is_checked = $themes_all || in_array( $stylesheet, $sel_themes, true );
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $label_extra is already escaped above
				echo '<label style="display:block"><input type="checkbox" name="brightleaf_digital_php_checker_themes[]" value="' . esc_attr( (string) $stylesheet ) . '"' . checked( $is_checked, true, false ) . '> ' . esc_html( $name . ' (' . $stylesheet . ')' ) . $label_extra . '</label>';
			}
		}
		echo '</div>';
		echo '<p><label><input type="checkbox" name="brightleaf_digital_php_checker_scan_parent_child" value="1"' . checked( $scan_parent_child, true, false ) . '> Also scan parent when a child theme is selected</label></p>';
		echo '</td></tr>';

		echo '<tr><th><label for="brightleaf-digital-php-checker-extra-excludes">Extra excludes</label></th><td><input type="text" id="brightleaf-digital-php-checker-extra-excludes" name="brightleaf_digital_php_checker_extra_excludes" value="' . esc_attr( $extra_excludes_raw ) . '" class="regular-text"> <span class="description">Comma-separated sniff codes to exclude if a scan fails.</span></td></tr>';
		echo '</tbody></table>';
		echo '<p><button type="submit" class="button button-primary">Run scan</button></p>';
		echo '</form>';

		// Results container for AJAX responses.
		echo '<div id="brightleaf-digital-php-checker-results"></div>';

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
			$html .= '<pre style="white-space:pre-wrap">' . self::h( $err1 ?: $json1 ) . '</pre>';
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
			$html .= '<pre style="white-space:pre-wrap">' . self::h( $err2 ?: $json2 ) . '</pre>';
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
			$html .= '<p class="brightleaf-digital-php-checker-summary--bad">Not compatible with PHP ' . self::h( $selected_target ) . ' (new issues: ' . (int) $count . '). Consider contacting the developer or finding a replacement.</p>';
			$html .= '<table class="widefat fixed striped"><thead><tr><th>File</th><th>Line</th><th>Col</th><th>Type</th><th>Message</th><th>Source</th></tr></thead><tbody>';
			foreach ( $msgs as $m ) {
				$file  = isset( $m['path'] ) ? (string) $m['path'] : '';
				$line  = isset( $m['line'] ) ? (int) $m['line'] : 0;
				$col   = isset( $m['column'] ) ? (int) $m['column'] : 0;
				$type  = isset( $m['type'] ) ? (string) $m['type'] : '';
				$msg   = isset( $m['message'] ) ? (string) $m['message'] : '';
				$src   = isset( $m['source'] ) ? (string) $m['source'] : '';
				$html .= '<tr class="' . self::h( $type ) . '"><td>' . self::h( preg_replace( '#^.*/wp-content/plugins/#', '', $file ) ) . '</td><td>' . $line . '</td><td>' . $col . '</td><td><strong>' . self::h( $type ) . '</strong></td><td>' . self::h( $msg ) . '</td><td><code>' . self::h( $src ) . '</code></td></tr>';
			}
			$html .= '</tbody></table>';
		}

		// Compatible plugins list.
		$incompatible = array_keys( $groups );
		$compatible   = array_values( array_diff( $plugins, $incompatible ) );
		if ( ! empty( $compatible ) ) {
			$html .= '<h2>Compatible plugins</h2><ul class="ul-disc">';
			foreach ( $compatible as $slug ) {
				$html .= '<li><strong>' . self::h( $slug ) . '</strong>: <span class="brightleaf-digital-php-checker-summary--ok">Compatible with PHP ' . self::h( $selected_target ) . ' (no new issues)</span></li>';
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
		check_ajax_referer( 'brightleaf_digital_php_checker', 'brightleaf_digital_php_checker_nonce' );

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

		if ( version_compare( $selected_target, $runtime, '<=' ) ) {
			wp_send_json_error( [ 'message' => 'Target PHP must be greater than runtime PHP ' . self::h( $runtime ) . '.' ] );
		}

		$plugins = $scan_all ? $all_plugins : $sel_plugins;
		if ( empty( $plugins ) ) {
			wp_send_json_error( [ 'message' => 'No plugins selected. Please choose plugins or enable "Scan all plugins".' ] );
		}

		$html = self::generate_results_html( $runtime, $selected_target, $include_warnings, $plugins, $extra_excludes );
		wp_send_json_success( [ 'html' => $html ] );
	}

	/**
	 * Generate a UUID-like job ID.
	 *
	 * @return string Job ID.
	 */
	private static function new_job_id(): string {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return wp_generate_uuid4();
		}
		return substr( md5( wp_rand() . '|' . microtime( true ) ), 0, 12 );
	}

	/**
	 * Load a job array from transient storage.
	 *
	 * @param string $job_id Job ID.
	 * @return array Job data or empty array if not found.
	 */
	private static function get_job( string $job_id ): array {
		$tid  = self::TRANSIENT_PREFIX . preg_replace( '/[^a-zA-Z0-9_\-]/', '', $job_id );
		$data = get_transient( $tid );
		return is_array( $data ) ? $data : [];
	}

	/**
	 * Persist a job array to transient storage.
	 *
	 * @param array $job Job data.
	 * @return void
	 */
	private static function save_job( array $job ): void {
		$job_id = isset( $job['id'] ) ? (string) $job['id'] : '';
		if ( '' === $job_id ) {
			return;
		}
		$tid = self::TRANSIENT_PREFIX . preg_replace( '/[^a-zA-Z0-9_\-]/', '', $job_id );
		set_transient( $tid, $job, self::JOB_TTL );
	}

	/**
	 * AJAX: Start a scan job asynchronously.
	 *
	 * Creates a job, schedules the first cron tick, and returns the job_id immediately.
	 *
	 * @return void
	 */
	public static function ajax_scan_start(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'Insufficient permissions.' ] );
		}
		check_ajax_referer( 'brightleaf_digital_php_checker', 'brightleaf_digital_php_checker_nonce' );

		$runtime     = self::get_runtime_major_minor();
		$all_plugins = self::list_plugins();
		$all_themes  = function_exists( 'wp_get_themes' ) ? wp_get_themes() : [];

		$parsed = self::parse_request( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified via check_ajax_referer.
		[
			'target'             => $selected_target,
			'include_warnings'   => $include_warnings,
			'scan_all'           => $scan_all,
			'plugins'            => $sel_plugins,
			'themes_all'         => $themes_all,
			'themes'             => $sel_themes,
			'scan_parent_child'  => $scan_parent_child,
			'extra_excludes'     => $extra_excludes,
		]       = $parsed;

		if ( version_compare( $selected_target, $runtime, '<=' ) ) {
			wp_send_json_error( [ 'message' => 'Target PHP must be greater than runtime PHP ' . self::h( $runtime ) . '.' ] );
		}

		$plugins = $scan_all ? $all_plugins : $sel_plugins;
		// Validate requested plugins exist.
		$plugins = array_values( array_intersect( array_map( 'strval', $plugins ), $all_plugins ) );

		// Build theme selection (show all by default if themes_all is true).
		if ( $themes_all ) {
			$themes_selected = array_map( 'strval', array_keys( $all_themes ) );
		} else {
			$themes_selected = array_values( array_intersect( array_map( 'strval', $sel_themes ), array_map( 'strval', array_keys( $all_themes ) ) ) );
		}

		$targets = self::build_targets( $plugins, $themes_selected, $scan_parent_child, $all_themes );
		if ( empty( $targets ) ) {
			wp_send_json_error( [ 'message' => 'No plugins or themes selected.' ] );
		}

		$job_id = self::new_job_id();
		$job    = [
			'id'               => $job_id,
			'created'          => time(),
			'updated'          => time(),
			'status'           => 'queued',
			'message'          => 'Queued',
			'progress'         => 0,
			'runtime'          => $runtime,
			'target'           => $selected_target,
			'include_warnings' => $include_warnings,
			'engine'           => self::cli_available() ? 'cli' : 'embedded',
			'targets'          => $targets,
			'extra_excludes'   => $extra_excludes,
			'current_index'    => 0,
			'per_target'       => [],
			'cancel_requested' => false,
			'paused'           => false,
			'final_html'       => '',
		];
		self::save_job( $job );

		// No cron scheduling. Progress will be driven by AJAX polling ticks.
		wp_send_json_success( [ 'job_id' => $job_id ] );
	}

	/**
	 * AJAX: Get job status for polling.
	 *
	 * @return void
	 */
	public static function ajax_scan_status(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'Insufficient permissions.' ] );
		}
		check_ajax_referer( 'brightleaf_digital_php_checker', 'brightleaf_digital_php_checker_nonce' );

		$job_id = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['job_id'] ) ) : '';// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified via check_ajax_referer.
		if ( '' === $job_id ) {
			wp_send_json_error( [ 'message' => 'Missing job_id.' ] );
		}
		$job = self::get_job( $job_id );
		if ( empty( $job ) ) {
			wp_send_json_error( [ 'message' => 'Job not found or expired.' ] );
		}

		// Drive work via AJAX tick when requested.
		$tick = isset( $_POST['tick'] ) ? (int) $_POST['tick'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce already verified.
		if ( 1 === $tick ) {
			$job = self::process_next_item( $job_id );
		}

		$data = [
			'status'   => isset( $job['status'] ) ? (string) $job['status'] : 'unknown',
			'progress' => isset( $job['progress'] ) ? (int) $job['progress'] : 0,
			'message'  => isset( $job['message'] ) ? (string) $job['message'] : '',
		];
		if ( 'done' === $data['status'] || 'cancelled' === $data['status'] ) {
			$data['html'] = isset( $job['final_html'] ) ? (string) $job['final_html'] : '';
		}
		if ( 'error' === $data['status'] && empty( $data['message'] ) ) {
			$data['message'] = 'Scan failed.';
		}
		wp_send_json_success( $data );
	}

	/**
     * Build scan targets from selected plugins and themes.
     *
     * @param array<int,string> $plugins           Plugin slugs.
     * @param array<int,string> $themes_stylesheet Theme stylesheet slugs.
     * @param bool              $include_parent    Include parent theme when child selected.
     * @param array             $all_themes        Array from wp_get_themes().
     * @return array<int,array{type:string,slug:string,path:string,label:string,key:string}>
     */
	private static function build_targets( array $plugins, array $themes_stylesheet, bool $include_parent, array $all_themes ): array {
		$targets = [];
		$added   = [];
		foreach ( $plugins as $slug ) {
			$path  = trailingslashit( WP_PLUGIN_DIR ) . $slug;
			$key   = 'plugin:' . $slug;
			$label = 'Plugin: ' . $slug;
			if ( isset( $added[ $key ] ) ) {
				continue; }
			$targets[]     = [
				'type'  => 'plugin',
				'slug'  => $slug,
				'path'  => $path,
				'label' => $label,
				'key'   => $key,
			];
			$added[ $key ] = true;
		}
		foreach ( $themes_stylesheet as $style ) {
			if ( ! isset( $all_themes[ $style ] ) ) {
				continue; }
			$path  = trailingslashit( get_theme_root( $style ) ) . $style;
			$key   = 'theme:' . $style;
			$name  = is_object( $all_themes[ $style ] ) ? (string) $all_themes[ $style ]->get( 'Name' ) : $style;
			$label = 'Theme: ' . $name . ' (' . $style . ')';
			if ( ! isset( $added[ $key ] ) ) {
				$targets[]     = [
					'type'  => 'theme',
					'slug'  => $style,
					'path'  => $path,
					'label' => $label,
					'key'   => $key,
				];
				$added[ $key ] = true;
			}
			if ( $include_parent ) {
				$parent = is_object( $all_themes[ $style ] ) ? (string) $all_themes[ $style ]->get( 'Template' ) : '';
				if ( $parent && isset( $all_themes[ $parent ] ) ) {
					$pkey = 'theme:' . $parent;
					if ( ! isset( $added[ $pkey ] ) ) {
						$ppath          = trailingslashit( get_theme_root( $parent ) ) . $parent;
						$pname          = is_object( $all_themes[ $parent ] ) ? (string) $all_themes[ $parent ]->get( 'Name' ) : $parent;
						$plabel         = 'Theme: ' . $pname . ' (' . $parent . ')';
						$targets[]      = [
							'type'  => 'theme',
							'slug'  => $parent,
							'path'  => $ppath,
							'label' => $plabel,
							'key'   => $pkey,
						];
						$added[ $pkey ] = true;
					}
				}
			}
		}
		return $targets;
	}

	/**
	 * Process one target step for the given job. Cooperative cancel/pause.
	 *
	 * @param string $job_id Job ID.
	 * @return array Updated job data.
	 */
	private static function process_next_item( string $job_id ): array {
		$job = self::get_job( $job_id );
		if ( empty( $job ) ) {
			return [];
		}
		if ( ! empty( $job['cancel_requested'] ) ) {
			$job['status']  = 'cancelled';
			$job['message'] = 'Cancelled.';
			$job['updated'] = time();
			// Build partial HTML from what we have.
			$targets           = isset( $job['targets'] ) && is_array( $job['targets'] ) ? $job['targets'] : [];
			$per_target        = isset( $job['per_target'] ) && is_array( $job['per_target'] ) ? $job['per_target'] : [];
			$job['final_html'] = self::build_final_html_from_targets( (string) $job['runtime'], (string) $job['target'], $targets, $per_target );
			self::save_job( $job );
			return $job;
		}
		if ( ! empty( $job['paused'] ) ) {
			$job['status']  = 'paused';
			$job['message'] = 'Paused.';
			$job['updated'] = time();
			self::save_job( $job );
			return $job;
		}
		$targets = isset( $job['targets'] ) && is_array( $job['targets'] ) ? $job['targets'] : [];
		$total   = count( $targets );
		$idx     = isset( $job['current_index'] ) ? (int) $job['current_index'] : 0;
		if ( 0 === $total ) {
			$job['status']  = 'error';
			$job['message'] = 'No scan targets.';
			$job['updated'] = time();
			self::save_job( $job );
			return $job;
		}
		$job['status']  = 'running';
		$job['updated'] = time();
		self::save_job( $job );
		if ( $idx < $total ) {
			$target         = $targets[ $idx ];
			$runtime        = isset( $job['runtime'] ) ? (string) $job['runtime'] : self::get_runtime_major_minor();
			$tver           = isset( $job['target'] ) ? (string) $job['target'] : '';
			$warn           = ! empty( $job['include_warnings'] );
			$excl           = isset( $job['extra_excludes'] ) && is_array( $job['extra_excludes'] ) ? $job['extra_excludes'] : [];
			$paths          = [ (string) $target['path'] ];
			list(, $json1,) = self::phpcs_scan_paths( $runtime, $warn, $paths, $excl );
			list(, $json2,) = self::phpcs_scan_paths( $tver, $warn, $paths, $excl );
			$report1        = is_string( $json1 ) && '' !== $json1 ? json_decode( $json1, true ) : null;
			$report2        = is_string( $json2 ) && '' !== $json2 ? json_decode( $json2, true ) : null;
			if ( is_array( $report1 ) && is_array( $report2 ) ) {
				$delta = self::compute_delta( $report1, $report2 );
				if ( count( $delta ) > self::PER_PLUGIN_MSG_LIMIT ) {
					$delta = array_slice( $delta, 0, self::PER_PLUGIN_MSG_LIMIT );
				}
				$messages = $delta;
			} else {
				$messages = [];
			}
			$key                       = (string) $target['key'];
			$job['per_target'][ $key ] = [
				'issues'   => count( $messages ),
				'messages' => $messages,
				'type'     => (string) $target['type'],
				'slug'     => (string) $target['slug'],
				'label'    => (string) $target['label'],
			];
			++$idx;
			$job['current_index'] = $idx;
			$job['progress']      = (int) floor( ( $idx / $total ) * 100 );
			$job['message']       = 'Processed ' . $idx . ' / ' . $total . ' items…';
			$job['updated']       = time();
			self::save_job( $job );
		}
		if ( $idx >= $total ) {
			// All done. Build HTML and store plugin badges.
			$per_target        = isset( $job['per_target'] ) && is_array( $job['per_target'] ) ? $job['per_target'] : [];
			$job['final_html'] = self::build_final_html_from_targets( (string) $job['runtime'], (string) $job['target'], $targets, $per_target );
			$job['status']     = 'done';
			$job['message']    = 'Completed.';
			$job['progress']   = 100;
			$job['updated']    = time();
			// Persist plugin badges.
			$results = [];
			foreach ( $targets as $t ) {
				if ( 'plugin' === $t['type'] ) {
					$entry                 = $per_target[ $t['key'] ] ?? [];
					$results[ $t['slug'] ] = [ 'issues' => (int) ( $entry['issues'] ?? 0 ) ];
				}
			}
			update_option(
                self::OPT_LAST_SCAN,
                [
					'runtime' => (string) $job['runtime'],
					'target'  => (string) $job['target'],
					'results' => $results,
				],
				false
                );
			self::save_job( $job );
		}
		return $job;
	}

	/**
	 * Build final results HTML from per-target data.
	 *
	 * @param string $runtime          Runtime PHP.
	 * @param string $selected_target  Target PHP.
	 * @param array  $targets          Targets list.
	 * @param array  $per_target       Per-target results.
	 * @return string HTML.
	 */
	private static function build_final_html_from_targets( string $runtime, string $selected_target, array $targets, array $per_target ): string {
		$html           = '<hr />';
		$html          .= '<h2>Results: Baseline ' . self::h( $runtime ) . ' → Target ' . self::h( $selected_target ) . '</h2>';
		$groups_plugins = [];
		$groups_themes  = [];
		foreach ( $targets as $t ) {
			$key   = (string) $t['key'];
			$entry = $per_target[ $key ] ?? [];
			$cnt   = (int) ( $entry['issues'] ?? 0 );
			if ( $cnt > 0 && isset( $entry['messages'] ) && is_array( $entry['messages'] ) ) {
				if ( 'plugin' === $t['type'] ) {
					$groups_plugins[ $t['slug'] ] = $entry['messages'];
				} else {
					$groups_themes[ $t['slug'] ] = $entry['messages'];
				}
			}
		}
		if ( empty( $groups_plugins ) && empty( $groups_themes ) ) {
			$html .= '<div class="notice notice-success"><p>All selected items show no new issues for PHP ' . self::h( $selected_target ) . ' compared to ' . self::h( $runtime ) . '. Compatible.</p></div>';
			return $html;
		}
		if ( ! empty( $groups_plugins ) ) {
			$html .= '<h2>Plugins</h2>';
			foreach ( $groups_plugins as $slug => $msgs ) {
				$count = is_array( $msgs ) ? count( $msgs ) : 0;
				$html .= '<h3 id="plugin-' . self::h( (string) $slug ) . '">' . self::h( (string) $slug ) . '</h3>';
				$html .= '<p class="brightleaf-digital-php-checker-summary--bad">Not compatible with PHP ' . self::h( $selected_target ) . ' (new issues: ' . (int) $count . '). Consider contacting the developer or finding a replacement.</p>';
				$html .= '<table class="widefat fixed striped"><thead><tr><th>File</th><th>Line</th><th>Col</th><th>Type</th><th>Message</th><th>Source</th></tr></thead><tbody>';
				foreach ( $msgs as $m ) {
					$file  = isset( $m['path'] ) ? (string) $m['path'] : '';
					$line  = isset( $m['line'] ) ? (int) $m['line'] : 0;
					$col   = isset( $m['column'] ) ? (int) $m['column'] : 0;
					$type  = isset( $m['type'] ) ? (string) $m['type'] : '';
					$msg   = isset( $m['message'] ) ? (string) $m['message'] : '';
					$src   = isset( $m['source'] ) ? (string) $m['source'] : '';
					$html .= '<tr class="' . self::h( $type ) . '"><td>' . self::h( preg_replace( '#^.*/wp-content/plugins/#', '', $file ) ) . '</td><td>' . $line . '</td><td>' . $col . '</td><td><strong>' . self::h( $type ) . '</strong></td><td>' . self::h( $msg ) . '</td><td><code>' . self::h( $src ) . '</code></td></tr>';
				}
				$html .= '</tbody></table>';
			}
		}
		if ( ! empty( $groups_themes ) ) {
			$html .= '<h2>Themes</h2>';
			foreach ( $groups_themes as $slug => $msgs ) {
				$count = is_array( $msgs ) ? count( $msgs ) : 0;
				$html .= '<h3 id="theme-' . self::h( (string) $slug ) . '">' . self::h( (string) $slug ) . '</h3>';
				$html .= '<p class="brightleaf-digital-php-checker-summary--bad">Not compatible with PHP ' . self::h( $selected_target ) . ' (new issues: ' . (int) $count . '). Consider contacting the developer or finding a replacement.</p>';
				$html .= '<table class="widefat fixed striped"><thead><tr><th>File</th><th>Line</th><th>Col</th><th>Type</th><th>Message</th><th>Source</th></tr></thead><tbody>';
				foreach ( $msgs as $m ) {
					$file  = isset( $m['path'] ) ? (string) $m['path'] : '';
					$line  = isset( $m['line'] ) ? (int) $m['line'] : 0;
					$col   = isset( $m['column'] ) ? (int) $m['column'] : 0;
					$type  = isset( $m['type'] ) ? (string) $m['type'] : '';
					$msg   = isset( $m['message'] ) ? (string) $m['message'] : '';
					$src   = isset( $m['source'] ) ? (string) $m['source'] : '';
					$html .= '<tr class="' . self::h( $type ) . '"><td>' . self::h( preg_replace( '#^.*/wp-content/themes/#', '', $file ) ) . '</td><td>' . $line . '</td><td>' . $col . '</td><td><strong>' . self::h( $type ) . '</strong></td><td>' . self::h( $msg ) . '</td><td><code>' . self::h( $src ) . '</code></td></tr>';
				}
				$html .= '</tbody></table>';
			}
		}
		return $html;
	}

	/**
	 * AJAX: Cancel a running scan.
	 */
	public static function ajax_scan_cancel(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'Insufficient permissions.' ] );
		}
		check_ajax_referer( 'brightleaf_digital_php_checker', 'brightleaf_digital_php_checker_nonce' );
		$job_id = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['job_id'] ) ) : '';// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified via check_ajax_referer.
		if ( '' === $job_id ) {
			wp_send_json_error( [ 'message' => 'Missing job_id.' ] );
		}
		$job = self::get_job( $job_id );
		if ( empty( $job ) ) {
			wp_send_json_error( [ 'message' => 'Job not found.' ] );
		}
		$job['cancel_requested'] = true;
		$job['status']           = 'cancelling';
		$job['updated']          = time();
		self::save_job( $job );
		wp_send_json_success( [ 'status' => 'cancelling' ] );
	}

	/**
	 * AJAX: Toggle pause/resume.
	 */
	public static function ajax_scan_toggle_pause(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => 'Insufficient permissions.' ] );
		}
		check_ajax_referer( 'brightleaf_digital_php_checker', 'brightleaf_digital_php_checker_nonce' );
		$job_id = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['job_id'] ) ) : '';// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified via check_ajax_referer.
		if ( '' === $job_id ) {
			wp_send_json_error( [ 'message' => 'Missing job_id.' ] );
		}
		$job = self::get_job( $job_id );
		if ( empty( $job ) ) {
			wp_send_json_error( [ 'message' => 'Job not found.' ] );
		}
		$paused         = ! empty( $job['paused'] );
		$job['paused']  = ! $paused;
		$job['status']  = $job['paused'] ? 'paused' : 'running';
		$job['message'] = $job['paused'] ? 'Paused.' : 'Resumed.';
		$job['updated'] = time();
		self::save_job( $job );
		wp_send_json_success( [ 'status' => $job['status'] ] );
	}
}

BrightLeaf_Digital_Php_Checker_Plugin::init();
