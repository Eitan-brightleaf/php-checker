=== PHP Compatibility Checker ===
Contributors: eitanatbrightleaf
Tags: php, compatibility, plugins, themes, scan
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

This plugin scans your installed plugins and themes for potential PHP compatibility issues when upgrading to newer PHP versions using PHP_CodeSniffer with the PHPCompatibilityWP standard.

== Description ==

PHP Compatibility Checker helps you assess whether your site’s code (plugins and themes) is likely to run on newer versions of PHP. It performs static analysis using PHP_CodeSniffer and the PHPCompatibilityWP ruleset to flag code patterns that are incompatible with the selected target PHP version.

What the plugin does (at a glance):
- Compares your current runtime PHP (baseline) to a selected target PHP version (8.0–8.4).
- Scans plugins and themes, then highlights only the new issues that would appear on the target version (the “delta”).
- Shows results in a clear report on the Tools screen and adds small badges on the Plugins list screen.
- Lets you pause, resume, or stop a running scan.

Important limitations of static analysis:
- Static analysis can miss issues in dynamic code paths and can generate false positives. Treat results as guidance, not guarantees. Always test site functionality on a staging environment before upgrading PHP in production.

== Features ==

- Select a target PHP version (8.0, 8.1, 8.2, 8.3, 8.4)
- Scan all plugins or select specific ones
- Scan all themes or select specific ones, with an option to also scan a parent if a child theme is selected
- Pause/Resume/Stop controls for long scans
- Clear report of only the new issues between baseline (current runtime) and target
- Plugin list badges showing a quick summary for the last scan

== Installation ==

1. Install the plugin via Plugins → Add New → Upload Plugin, or place the `bld-php-compatibility-checker` folder into `wp-content/plugins/`.
2. Activate the plugin through the “Plugins” menu in WordPress.
3. Go to Tools → PHP Compatibility Checker.
4. Choose a Target PHP version higher than your current runtime.
5. Select what to scan (plugins and/or themes) and click “Run scan”.

== Frequently Asked Questions ==

= What PHP versions can I target? =
You can select one of: 8.0, 8.1, 8.2, 8.3, or 8.4.

= What is the minimum PHP version required to run this plugin? =
The plugin requires PHP 7.4+ to run.

= Does this modify my code? =
No. It only analyzes code and reports findings.

= Why are there false positives or missing issues? =
Static analysis examines code without executing it. Dynamic patterns, conditional code paths, and environment-specific behavior can cause both false positives and false negatives. Use the results as guidance and verify on a staging site.

= Does it scan MU-plugins? =
No. MU-plugins are intentionally skipped.

= Do I need WP-Cron for scans? =
No. Scans advance via AJAX polling while the Tools page is open.

== Privacy ==
All analysis runs locally on your server. No data is sent to external services by this plugin.

== Changelog ==
= 1.0.0 =
- Initial release
- Scans plugins and themes against target PHP versions (8.0–8.4)
- Pause/Resume/Stop controls
- CLI-first engine with embedded fallback
- AJAX-driven progress (no WP-Cron)
- Plugin list badges for the last scan summary
