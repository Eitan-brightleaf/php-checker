(function ($) {
	$(function () {
		const $form = $('#brightleaf-digital-php-checker-form');
		if ($form.length === 0) {
			return;
		}

		const $results = $('#brightleaf-digital-php-checker-results');
		const ajaxCfg =
			typeof brightleaf_digital_php_checker_Ajax !== 'undefined'
				? brightleaf_digital_php_checker_Ajax
				: {};
		const ajaxUrl =
			ajaxCfg.ajaxUrl || (typeof ajaxurl !== 'undefined' ? ajaxurl : '');
		const pollInterval = ajaxCfg.pollInterval
			? parseInt(ajaxCfg.pollInterval, 10)
			: 3000;
		let pollTimer = null;
		let currentJobId = null;

		function escapeHtml(str) {
			return $('<div/>').text(String(str)).html();
		}

		function setControlsDisabled(disabled) {
			$('#blpc-pause, #blpc-stop').prop('disabled', !!disabled);
		}

		function renderControls() {
			if ($('#blpc-controls').length) {
				return;
			}
			const $wrap = $(
				'<div id="blpc-controls" style="margin:10px 0;"></div>'
			);
			const $pause = $(
				'<button type="button" class="button">Pause</button>'
			).attr('id', 'blpc-pause');
			const $stop = $(
				'<button type="button" class="button">Stop</button>'
			)
				.attr('id', 'blpc-stop')
				.css('margin-left', '6px');
			$wrap.append($pause, $stop);
			$results.before($wrap);
			$pause.on('click', function () {
				if (!currentJobId) {
					return;
				}
				// Immediate UI feedback: Pausing…
				renderProgress(
					'pausing',
					$('#blpc-progress').data('pct') || 0,
					'Pausing…'
				);
				setControlsDisabled(true);
				const data = $form.serializeArray();
				data.push({
					name: 'action',
					value: 'brightleaf_digital_php_checker_scan_toggle_pause',
				});
				data.push({ name: 'job_id', value: currentJobId });
				$.post(ajaxUrl, $.param(data)).done(function (resp) {
					// After server toggles, next poll will reflect paused/running.
					setControlsDisabled(false);
					if (resp && resp.success && resp.data && resp.data.status) {
						const st = resp.data.status;
						$('#blpc-pause').text(
							st === 'paused' ? 'Resume' : 'Pause'
						);
						if (st === 'paused') {
							renderProgress(
								'paused',
								$('#blpc-progress').data('pct') || 0,
								'Paused.'
							);
						} else {
							renderProgress(
								'running',
								$('#blpc-progress').data('pct') || 0,
								'Resumed.'
							);
						}
					}
					// Trigger an immediate status tick to update UI promptly.
					if (currentJobId) {
						pollStatus(currentJobId);
					}
				});
			});
			$stop.on('click', function () {
				if (!currentJobId) {
					return;
				}
				// Immediate UI feedback: Cancelling… and disable buttons.
				renderProgress(
					'cancelling',
					$('#blpc-progress').data('pct') || 0,
					'Cancelling…'
				);
				$('#blpc-stop').text('Stopping…');
				setControlsDisabled(true);
				const data = $form.serializeArray();
				data.push({
					name: 'action',
					value: 'brightleaf_digital_php_checker_scan_cancel',
				});
				data.push({ name: 'job_id', value: currentJobId });
				$.post(ajaxUrl, $.param(data)).always(function () {
					// Kick an immediate poll so we transition to cancelled ASAP.
					if (currentJobId) {
						pollStatus(currentJobId);
					}
				});
			});
		}

		function renderProgress(status, progress, message) {
			const pct = parseInt(progress, 10) || 0;
			const safeMsg = message ? escapeHtml(message) : '';
			$results.html(
				'<div id="blpc-progress" class="notice notice-info" data-pct="' +
					pct +
					'"><p>Scan status: ' +
					escapeHtml(status) +
					' (' +
					pct +
					'%). ' +
					safeMsg +
					'</p></div>'
			);
		}

		function pollStatus(jobId) {
			const data = $form.serializeArray();
			data.push({
				name: 'action',
				value: 'brightleaf_digital_php_checker_scan_status',
			});
			data.push({ name: 'job_id', value: jobId });
			data.push({ name: 'tick', value: 1 });
			$.post(ajaxUrl, $.param(data))
				.done(function (resp) {
					if (!resp || !resp.success || !resp.data) {
						$results.html(
							'<div class="notice notice-error"><p>Unexpected polling response.</p></div>'
						);
						clearInterval(pollTimer);
						pollTimer = null;
						return;
					}
					const d = resp.data;
					if (d.status === 'done' || d.status === 'cancelled') {
						clearInterval(pollTimer);
						pollTimer = null;
						currentJobId = null;
						$('#blpc-controls').remove();
						$results.html(
							d.html ||
								'<div class="notice notice-info"><p>Scan ' +
									(d.status === 'done'
										? 'completed'
										: 'cancelled') +
									'.</p></div>'
						);
						return;
					}
					if (d.status === 'error') {
						clearInterval(pollTimer);
						pollTimer = null;
						currentJobId = null;
						$('#blpc-controls').remove();
						const safe = escapeHtml(d.message || 'Scan failed.');
						$results.html(
							'<div class="notice notice-error"><p>' +
								safe +
								'</p></div>'
						);
						return;
					}
					if (d.status === 'paused') {
						$('#blpc-pause').text('Resume');
						setControlsDisabled(false);
					} else if (d.status === 'cancelling') {
						$('#blpc-pause').text('Pause');
						$('#blpc-stop').text('Stopping…');
						setControlsDisabled(true);
					} else {
						$('#blpc-pause').text('Pause');
						setControlsDisabled(false);
					}
					renderProgress(
						d.status || 'running',
						parseInt(d.progress || 0, 10),
						d.message || ''
					);
				})
				.fail(function () {
					/* keep polling */
				});
		}

		$form.on('submit', function (e) {
			e.preventDefault();
			const data = $form.serializeArray();
			data.push({
				name: 'action',
				value: 'brightleaf_digital_php_checker_scan_start',
			});
			$results.html('<p>Starting scan…</p>');
			$.post(ajaxUrl, $.param(data))
				.done(function (resp) {
					if (resp && resp.success && resp.data && resp.data.job_id) {
						currentJobId = resp.data.job_id;
						renderControls();
						renderProgress(
							'queued',
							0,
							'Job ' + currentJobId + ' created.'
						);
						if (pollTimer) {
							clearInterval(pollTimer);
						}
						pollTimer = setInterval(function () {
							pollStatus(currentJobId);
						}, pollInterval);
						pollStatus(currentJobId);
						return;
					}
					const raw =
						resp && resp.data && resp.data.message
							? resp.data.message
							: 'Unexpected error';
					const safe = escapeHtml(raw);
					$results.html(
						'<div class="notice notice-error"><p>' +
							safe +
							'</p></div>'
					);
				})
				.fail(function () {
					$results.html(
						'<div class="notice notice-error"><p>AJAX request failed.</p></div>'
					);
				});
		});
	});
})(jQuery);
