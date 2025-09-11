(function ($) {
	$(function () {
		const $form = $('#pcd-form');
		if ($form.length === 0) {
			return;
		}

		const $results = $('#pcd-results');
		const ajaxUrl = (typeof pcdAjax !== 'undefined' && pcdAjax.ajaxUrl) ? pcdAjax.ajaxUrl : (typeof ajaxurl !== 'undefined' ? ajaxurl : '');
		const pollInterval = (typeof pcdAjax !== 'undefined' && pcdAjax.pollInterval) ? parseInt(pcdAjax.pollInterval, 10) : 3000;
		let pollTimer = null;

		function escapeHtml(str) {
			return $('<div/>').text(String(str)).html();
		}

		function renderProgress(status, progress, message) {
			const safeMsg = message ? escapeHtml(message) : '';
			$results.html('<div class="notice notice-info"><p>Scan status: ' + escapeHtml(status) + ' (' + (progress|0) + '%). ' + safeMsg + '</p></div>');
		}

		function pollStatus(jobId) {
			const data = $form.serializeArray();
			data.push({ name: 'action', value: 'pcd_scan_status' });
			data.push({ name: 'job_id', value: jobId });
			$.post(ajaxUrl, $.param(data))
				.done(function (resp) {
					if (!resp || !resp.success || !resp.data) {
						$results.html('<div class="notice notice-error"><p>Unexpected polling response.</p></div>');
						clearInterval(pollTimer); pollTimer = null; return;
					}
					const d = resp.data;
					if (d.status === 'done') {
						clearInterval(pollTimer); pollTimer = null;
						$results.html(d.html || '<div class="notice notice-success"><p>Scan completed.</p></div>');
						return;
					}
					if (d.status === 'error') {
						clearInterval(pollTimer); pollTimer = null;
						const safe = escapeHtml(d.message || 'Scan failed.');
						$results.html('<div class="notice notice-error"><p>' + safe + '</p></div>');
						return;
					}
					renderProgress(d.status || 'running', parseInt(d.progress || 0, 10), d.message || '');
				})
				.fail(function () {
					// Keep polling; transient network blip.
				});
		}

		$form.on('submit', function (e) {
			e.preventDefault();
			const data = $form.serializeArray();
			data.push({ name: 'action', value: 'pcd_scan_start' });

			$results.html('<p>Starting scan…</p>');

			$.post(ajaxUrl, $.param(data))
				.done(function (resp) {
					if (resp && resp.success && resp.data && resp.data.job_id) {
						const jobId = resp.data.job_id;
						renderProgress('queued', 0, 'Job ' + jobId + ' created.');
						if (pollTimer) { clearInterval(pollTimer); }
						pollTimer = setInterval(function () { pollStatus(jobId); }, pollInterval);
						// Also trigger an immediate poll to show quick feedback.
						pollStatus(jobId);
						return;
					}
					const raw = (resp && resp.data && resp.data.message) ? resp.data.message : 'Unexpected error';
					const safe = escapeHtml(raw);
					$results.html('<div class="notice notice-error"><p>' + safe + '</p></div>');
				})
				.fail(function () {
					$results.html('<div class="notice notice-error"><p>AJAX request failed.</p></div>');
				});
		});
	});
})(jQuery);
