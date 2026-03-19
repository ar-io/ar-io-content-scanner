/* block.js — Manual block tab logic */

document.addEventListener('alpine:init', function () {
  var TX_ID_RE = /^[A-Za-z0-9_-]{43}$/;

  Alpine.data('blockTab', function () {
    return {
      txInput: '',
      reason: '',
      loading: false,
      error: '',
      validationError: '',
      recentBlocks: [],

      confirmDialog: {
        show: false,
        txIds: [],
        reason: '',
        progressText: ''
      },

      parseTxIds() {
        if (!this.txInput.trim()) return [];
        return this.txInput.split(/[\n,]+/)
          .map(function (s) { return s.trim(); })
          .filter(function (s) { return s.length > 0; });
      },

      validateTxIds() {
        var ids = this.parseTxIds();
        if (ids.length === 0) {
          this.validationError = 'At least one TX ID is required';
          return null;
        }
        if (ids.length > 100) {
          this.validationError = 'Maximum 100 TX IDs at once';
          return null;
        }
        var invalid = [];
        for (var i = 0; i < ids.length; i++) {
          if (!TX_ID_RE.test(ids[i])) {
            invalid.push(ids[i].substring(0, 20) + (ids[i].length > 20 ? '...' : ''));
          }
        }
        if (invalid.length > 0) {
          this.validationError = 'Invalid TX ID' + (invalid.length > 1 ? 's' : '') + ': ' + invalid.slice(0, 3).join(', ') + (invalid.length > 3 ? ' (+' + (invalid.length - 3) + ' more)' : '');
          return null;
        }
        // Deduplicate
        var seen = {};
        var unique = [];
        for (var j = 0; j < ids.length; j++) {
          if (!seen[ids[j]]) {
            seen[ids[j]] = true;
            unique.push(ids[j]);
          }
        }
        this.validationError = '';
        return unique;
      },

      promptBlock() {
        var ids = this.validateTxIds();
        if (!ids) return;
        this.confirmDialog = {
          show: true,
          txIds: ids,
          reason: this.reason.trim(),
          progressText: ''
        };
      },

      async executeBlock() {
        this.loading = true;
        this.error = '';
        var dialog = this.confirmDialog;
        var isSingle = dialog.txIds.length === 1;

        if (!isSingle) {
          dialog.progressText = 'Processing ' + dialog.txIds.length + ' transactions...';
        }

        try {
          var payload = isSingle
            ? { tx_id: dialog.txIds[0], reason: dialog.reason }
            : { tx_ids: dialog.txIds, reason: dialog.reason };

          var resp = await api('/api/admin/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (!resp.ok) {
            var errData = await resp.json().catch(function () { return {}; });
            throw new Error(errData.detail || 'Request failed (HTTP ' + resp.status + ')');
          }
          var result = await resp.json();
          dialog.show = false;

          var now = new Date().toLocaleString();
          if (isSingle) {
            this.recentBlocks.unshift({
              tx_id: result.tx_id,
              reason: dialog.reason,
              blocked: result.blocked,
              status: result.blocked ? 'blocked' : 'gateway_failed',
              time: now
            });
            var msg = result.blocked
              ? 'Transaction blocked successfully'
              : 'Verdict saved but gateway block failed';
            if (result.already_existed) msg += ' (overwrote existing verdict)';
            Alpine.store('toast').show(msg, result.blocked ? 'success' : 'error');
          } else {
            this._handleBulkResult(result, dialog.reason, now);
          }

          this.txInput = '';
          this.reason = '';
        } catch (e) {
          dialog.show = false;
          this.error = e.message || 'Failed to block transactions';
          Alpine.store('toast').show('Block failed: ' + (e.message || 'Unknown error'), 'error');
        }
        this.loading = false;
      },

      _handleBulkResult(result, reason, now) {
        var self = this;

        // Add successful items to recent blocks
        if (result.results && result.results.length > 0) {
          result.results.forEach(function (r) {
            self.recentBlocks.unshift({
              tx_id: r.tx_id,
              reason: reason,
              blocked: r.blocked,
              status: r.blocked ? 'blocked' : 'gateway_failed',
              time: now
            });
          });
        }

        // Add validation-rejected items to recent blocks
        if (result.errors && result.errors.length > 0) {
          result.errors.forEach(function (e) {
            self.recentBlocks.unshift({
              tx_id: e.tx_id || '(invalid)',
              reason: reason,
              blocked: false,
              status: 'invalid',
              time: now
            });
          });
        }

        // Build a clear summary toast
        var totalAttempted = result.succeeded + result.failed;
        var blockedCount = result.results
          ? result.results.filter(function (r) { return r.blocked; }).length
          : 0;
        var gatewayFailed = result.succeeded - blockedCount;
        var parts = [];

        if (blockedCount > 0) parts.push(blockedCount + ' blocked');
        if (gatewayFailed > 0) parts.push(gatewayFailed + ' saved (gateway failed)');
        if (result.failed > 0) parts.push(result.failed + ' skipped (invalid)');

        var msg = parts.join(', ');
        // Capitalize first letter
        msg = msg.charAt(0).toUpperCase() + msg.slice(1);
        msg += ' \u2014 ' + totalAttempted + ' total';

        var type = blockedCount === totalAttempted ? 'success' : (blockedCount > 0 ? 'success' : 'error');
        Alpine.store('toast').show(msg, type);
      }
    };
  });
});
