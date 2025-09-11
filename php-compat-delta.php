<?php
/**
 * Plugin Name: PHP Compatibility Delta
 * Description: Scan WordPress plugins for new PHPCompatibility issues between the current runtime PHP and a single target version. Outputs inline HTML; supports warnings opt-in. Stores a note next to each plugin name with the latest scan result.
 * Version: 0.1.0
 * Author: Brightleaf
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; }

class PCD_Plugin {
	const OPT_LAST_SCAN = 'pcd_last_scan_results';

	public static function init(): void {
		add_action( 'admin_menu', [ __CLASS__, 'register_tools_page' ] );
		add_action( 'admin_init', [ __CLASS__, 'maybe_bootstrap' ] );
		add_action( 'admin_head', [ __CLASS__, 'admin_head_css' ] );
		add_filter( 'plugin_row_meta', [ __CLASS__, 'plugin_row_meta_note' ], 10, 2 );
	}

	public static function maybe_bootstrap(): void {
		// Placeholder for future dependency checks if needed.
	}

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

	private static function h( string $s ): string {
		return htmlspecialchars( $s, ENT_QUOTES, 'UTF-8' );
	}

	private static function get_runtime_major_minor(): string {
		$ver = PHP_VERSION; // e.g., 8.3.6
		if ( preg_match( '/^(\d+)\.(\d+)/', $ver, $m ) ) {
			return $m[1] . '.' . $m[2];
		}
		return $ver;
	}

	private static function get_available_targets(): array {
		return [ '8.0', '8.1', '8.2', '8.3', '8.4' ];
	}

	private static function list_plugins(): array {
		$base = WP_PLUGIN_DIR;
		$dirs = @scandir( $base );
		if ( ! is_array( $dirs ) ) {
			return []; }
		$plugins = [];
		foreach ( $dirs as $d ) {
			if ( $d === '.' || $d === '..' ) {
				continue; }
			$path = $base . '/' . $d;
			if ( is_dir( $path ) ) {
				$plugins[] = $d;
			}
		}
		sort( $plugins );
		return $plugins;
	}

	private static function find_phpcs_binary(): string {
		// Prefer plugin-local vendor first (after composer install), then root vendor.
		$local = plugin_dir_path( __FILE__ ) . 'vendor/bin/phpcs';
		if ( file_exists( $local ) && is_executable( $local ) ) {
			return $local; }
		$root = ABSPATH . 'vendor/bin/phpcs';
		return $root;
	}

	private static function build_phpcs_cmd( string $php_minor, bool $include_warnings, array $targets, array $extra_excludes ): array {
		$bin      = self::find_phpcs_binary();
		$ignore   = '*/tests/*,*/Tests/*,*/test/*,*/Test/*,*/__tests__/*,*/spec/*,*/Spec/*,*/examples/*,*/example/*,*/Fixtures/*,*/fixtures/*,*/vendor/*/tests/*,*/vendor/*/*Tests/*,*/vendor_prefixed/*/Tests/*,*/vendor-scoped/*/Tests/*,*/third-party/*/Tests/*';
		$args     = [
			escapeshellarg( $bin ),
			'--parallel=6',
			'--report=json',
			'--standard=PHPCompatibilityWP',
			'--extensions=php',
			'--runtime-set',
			'testVersion',
			escapeshellarg( $php_minor . '-' . $php_minor ),
			'--ignore=' . escapeshellarg( $ignore ),
		];
		$excludes = array_merge( [ 'PHPCompatibility.ParameterValues.RemovedIconvEncoding' ], $extra_excludes );
		if ( ! empty( $excludes ) ) {
			$args[] = '--exclude=' . escapeshellarg( implode( ',', array_unique( array_filter( $excludes ) ) ) );
		}
		if ( ! $include_warnings ) {
			$args[] = '--warning-severity=0';
		}
		foreach ( $targets as $t ) {
			$args[] = escapeshellarg( $t ); }
		return $args;
	}

	private static function run_cmd( array $cmd_parts ): array {
		$cmd        = implode( ' ', $cmd_parts );
		$descriptor = [
			1 => [ 'pipe', 'w' ],
			2 => [ 'pipe', 'w' ],
		];
		$proc       = proc_open( $cmd, $descriptor, $pipes, ABSPATH );
		$out        = '';
		$err        = '';
		$code       = 1;
		if ( is_resource( $proc ) ) {
			$out = stream_get_contents( $pipes[1] );
			$err = stream_get_contents( $pipes[2] );
			foreach ( $pipes as $p ) {
				if ( is_resource( $p ) ) {
					fclose( $p ); }
			}
			$code = proc_close( $proc );
		}
		return [ $code, $out, $err, $cmd ];
	}

	private static function phpcs_scan( string $php_minor, bool $include_warnings, array $plugin_slugs, array $extra_excludes ): array {
		$paths = [];
		foreach ( $plugin_slugs as $slug ) {
			$paths[] = WP_PLUGIN_DIR . '/' . $slug; }
		if ( empty( $paths ) ) {
			$paths[] = WP_PLUGIN_DIR; }
		return self::run_cmd( self::build_phpcs_cmd( $php_minor, $include_warnings, $paths, $extra_excludes ) );
	}

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

	private static function msg_key( array $m ): string {
		$path    = isset( $m['path'] ) ? (string) $m['path'] : '';
		$source  = isset( $m['source'] ) ? (string) $m['source'] : '';
		$message = isset( $m['message'] ) ? (string) $m['message'] : '';
		return $path . '|' . $source . '|' . $message;
	}

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

	private static function plugin_slug_from_path( string $path ): string {
		$rel = str_replace( '\\', '/', $path );
		$pos = strpos( $rel, 'wp-content/plugins/' );
		if ( false !== $pos ) {
			$sub   = substr( $rel, $pos + strlen( 'wp-content/plugins/' ) );
			$parts = explode( '/', $sub );
			return $parts[0] ?? 'unknown';
		}
		return 'unknown';
	}

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

	public static function admin_head_css(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$hook   = $screen ? $screen->id : '';
		$css    = '';
		if ( $hook === 'tools_page_php-compat-delta' ) {
			$css .= '.pcd-wrap .pcd-meta{color:#555}.pcd-plugin-list{max-height:220px;overflow:auto;border:1px solid #ddd;padding:8px}.pcd-summary--ok{color:#0a8a0a;font-weight:600}.pcd-summary--bad{color:#b00020;font-weight:600} .pcd-toplink{font-size:12px;margin-left:6px}';
		}
		// Plugin list badges
		$css .= '.pcd-badge{display:inline-block;margin-left:6px;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:600} .pcd-badge--ok{background:#e7f7ea;color:#0a8a0a;border:1px solid #bfe6c7} .pcd-badge--bad{background:#fde7ea;color:#b00020;border:1px solid #f6c2ca}';
		if ( $css ) {
			echo '<style>' . $css . '</style>'; }
	}

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
			$cls     = $issues > 0 ? 'pcd-badge pcd-badge--bad' : 'pcd-badge pcd-badge--ok';
			$txt     = $issues > 0
				? ( 'PHP ' . $runtime . '→' . $target . ': ' . $issues . ' new issues' )
				: ( 'PHP ' . $runtime . '→' . $target . ': OK' );
			$meta[]  = '<span class="' . self::h( $cls ) . '">' . self::h( $txt ) . '</span>';
		}
		return $meta;
	}

	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' ); }
		$runtime     = self::get_runtime_major_minor();
		$targets     = self::get_available_targets();
		$all_plugins = self::list_plugins();

		$selected_target  = isset( $_POST['pcd_target'] ) ? preg_replace( '/[^0-9\.]*/', '', (string) $_POST['pcd_target'] ) : '';
		$include_warnings = ! empty( $_POST['pcd_include_warnings'] );
		$scan_all         = ! empty( $_POST['pcd_scan_all'] );
		$sel_plugins      = isset( $_POST['pcd_plugins'] ) && is_array( $_POST['pcd_plugins'] ) ? array_map( 'sanitize_text_field', $_POST['pcd_plugins'] ) : [];
		$extra_excludes   = isset( $_POST['pcd_extra_excludes'] ) ? array_filter( array_map( 'trim', explode( ',', (string) $_POST['pcd_extra_excludes'] ) ) ) : [];
		$nonce_ok         = isset( $_POST['pcd_nonce'] ) && wp_verify_nonce( (string) $_POST['pcd_nonce'], 'pcd' );

		echo '<div class="wrap pcd-wrap">';
		echo '<h1>PHP Compatibility Delta</h1>';
		echo '<p class="pcd-meta">Baseline: <code>' . self::h( $runtime ) . '</code> (current runtime). Choose one target to compare against.</p>';

		echo '<form method="post">';
		wp_nonce_field( 'pcd', 'pcd_nonce' );
		echo '<table class="form-table"><tbody>';
		echo '<tr><th><label for="pcd_target">Target PHP</label></th><td><select id="pcd_target" name="pcd_target">';
		foreach ( $targets as $t ) {
			$sel = ( $selected_target === $t ) ? ' selected' : '';
			echo '<option value="' . self::h( $t ) . '"' . $sel . '>' . self::h( $t ) . '</option>';
		}
		echo '</select></td></tr>';

		echo '<tr><th><label for="pcd_include_warnings">Include warnings</label></th><td><label><input type="checkbox" id="pcd_include_warnings" name="pcd_include_warnings" value="1"' . ( $include_warnings ? ' checked' : '' ) . '> Include warnings (uncheck to hide)</label></td></tr>';

		echo '<tr><th>Plugins</th><td>';
		echo '<label><input type="checkbox" name="pcd_scan_all" value="1"' . ( $scan_all ? ' checked' : '' ) . '> Scan all plugins</label>';
		echo '<p><em>Or select specific plugins:</em></p>';
		echo '<div class="pcd-plugin-list">';
		foreach ( $all_plugins as $slug ) {
			$checked = in_array( $slug, $sel_plugins, true ) ? ' checked' : '';
			echo '<label style="display:block"><input type="checkbox" name="pcd_plugins[]" value="' . self::h( $slug ) . '"' . $checked . '> ' . self::h( $slug ) . '</label>';
		}
		echo '</div>';
		echo '</td></tr>';

		echo '<tr><th><label for="pcd_extra_excludes">Extra excludes</label></th><td><input type="text" id="pcd_extra_excludes" name="pcd_extra_excludes" value="' . self::h( isset( $_POST['pcd_extra_excludes'] ) ? (string) $_POST['pcd_extra_excludes'] : '' ) . '" class="regular-text"> <span class="description">Comma-separated sniff codes to exclude if a scan fails.</span></td></tr>';
		echo '</tbody></table>';
		echo '<p><button type="submit" class="button button-primary">Run scan</button></p>';
		echo '</form>';

		if ( $nonce_ok && $selected_target ) {
			$plugins = $scan_all ? $all_plugins : $sel_plugins;
			if ( empty( $plugins ) ) {
				echo '<div class="notice notice-warning"><p>No plugins selected. Please choose plugins or enable "Scan all plugins".</p></div>';
				echo '</div>';
				return;
			}

			// Baseline scan
			list( $code1, $json1, $err1, $cmd1 ) = self::phpcs_scan( $runtime, $include_warnings, $plugins, $extra_excludes );
			if ( $code1 !== 0 ) {
				echo '<div class="notice notice-error"><p>Baseline scan failed (PHP ' . self::h( $runtime ) . ').</p>';
				echo '<p><strong>Command:</strong> <code>' . self::h( $cmd1 ) . '</code></p>';
				echo '<pre style="white-space:pre-wrap">' . self::h( $err1 ?: $json1 ) . '</pre>';
				echo '<p>Try adding the failing sniff(s) to Extra excludes above and rerun.</p></div>';
				echo '</div>';
				return;
			}
			$report1 = json_decode( $json1, true );
			if ( ! is_array( $report1 ) ) {
				echo '<div class="notice notice-error"><p>Could not parse baseline JSON output.</p></div></div>';
				return;
			}

			// Target scan
			list( $code2, $json2, $err2, $cmd2 ) = self::phpcs_scan( $selected_target, $include_warnings, $plugins, $extra_excludes );
			if ( $code2 !== 0 ) {
				echo '<div class="notice notice-error"><p>Target scan failed (PHP ' . self::h( $selected_target ) . ').</p>';
				echo '<p><strong>Command:</strong> <code>' . self::h( $cmd2 ) . '</code></p>';
				echo '<pre style="white-space:pre-wrap">' . self::h( $err2 ?: $json2 ) . '</pre>';
				echo '<p>Try adding the failing sniff(s) to Extra excludes above and rerun.</p></div>';
				echo '</div>';
				return;
			}
			$report2 = json_decode( $json2, true );
			if ( ! is_array( $report2 ) ) {
				echo '<div class="notice notice-error"><p>Could not parse target JSON output.</p></div></div>';
				return;
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

			echo '<hr />';
			echo '<h2>Results: Baseline ' . self::h( $runtime ) . ' → Target ' . self::h( $selected_target ) . '</h2>';

			if ( empty( $groups ) ) {
				echo '<div class="notice notice-success"><p>All selected plugins show no new issues for PHP ' . self::h( $selected_target ) . ' compared to ' . self::h( $runtime ) . '. Compatible.</p></div>';
				echo '</div>';
				return;
			}

			// Incompatible plugins with details
			foreach ( $groups as $slug => $msgs ) {
				$count = count( $msgs );
				echo '<h3 id="plugin-' . self::h( $slug ) . '">' . self::h( $slug ) . '</h3>';
				echo '<p class="pcd-summary--bad">Not compatible with PHP ' . self::h( $selected_target ) . ' (new issues: ' . (int) $count . '). Consider contacting the developer or finding a replacement.</p>';
				echo '<table class="widefat fixed striped"><thead><tr><th>File</th><th>Line</th><th>Col</th><th>Type</th><th>Message</th><th>Source</th></tr></thead><tbody>';
				foreach ( $msgs as $m ) {
					$file = isset( $m['path'] ) ? (string) $m['path'] : '';
					$line = isset( $m['line'] ) ? (int) $m['line'] : 0;
					$col  = isset( $m['column'] ) ? (int) $m['column'] : 0;
					$type = isset( $m['type'] ) ? (string) $m['type'] : '';
					$msg  = isset( $m['message'] ) ? (string) $m['message'] : '';
					$src  = isset( $m['source'] ) ? (string) $m['source'] : '';
					echo '<tr class="' . self::h( $type ) . '"><td>' . self::h( preg_replace( '#^.*/wp-content/plugins/#', '', $file ) ) . '</td><td>' . (int) $line . '</td><td>' . (int) $col . '</td><td><strong>' . self::h( $type ) . '</strong></td><td>' . self::h( $msg ) . '</td><td><code>' . self::h( $src ) . '</code></td></tr>';
				}
				echo '</tbody></table>';
			}

			// Compatible plugins list
			$incompatible = array_keys( $groups );
			$compatible   = array_values( array_diff( $plugins, $incompatible ) );
			if ( ! empty( $compatible ) ) {
				echo '<h2>Compatible plugins</h2><ul class="ul-disc">';
				foreach ( $compatible as $slug ) {
					echo '<li><strong>' . self::h( $slug ) . '</strong>: <span class="pcd-summary--ok">Compatible with PHP ' . self::h( $selected_target ) . ' (no new issues)</span></li>';
				}
				echo '</ul>';
			}
		}

		echo '</div>';
	}
}

PCD_Plugin::init();
