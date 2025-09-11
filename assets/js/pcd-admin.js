(function ($) {
	$(function () {
		const $form = $('#pcd-form');
		if ($form.length === 0) {
			return;
		}

		const $results = $('#pcd-results');

		$form.on('submit', function (e) {
			e.preventDefault();
			const data = $form.serializeArray();
			data.push({ name: 'action', value: 'pcd_scan' });

			$results.html('<p>Running scan…</p>');

			$.post(ajaxurl, $.param(data))
				.done(function (resp) {
					if (resp && resp.success && resp.data && resp.data.html) {
						$results.html(resp.data.html);
						return;
					}
					const raw = (resp && resp.data && resp.data.message) ? resp.data.message : 'Unexpected error';
					const safe = $('<div/>').text(String(raw)).html();
					$results.html('<div class="notice notice-error"><p>' + safe + '</p></div>');
				})
				.fail(function () {
					$results.html('<div class="notice notice-error"><p>AJAX request failed.</p></div>');
				});
		});
	});
})(jQuery);
