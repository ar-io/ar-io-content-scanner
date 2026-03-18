/* block.js — Manual block tab logic */

document.addEventListener('alpine:init', function () {
  Alpine.data('blockTab', function () {
    return {
      txId: '',
      reason: '',
      loading: false,
      error: '',
      validationError: '',
      recentBlocks: [],

      confirmDialog: {
        show: false,
        txId: '',
        reason: ''
      },

      validateTxId() {
        var id = this.txId.trim();
        if (!id) {
          this.validationError = 'TX ID is required';
          return false;
        }
        if (!/^[A-Za-z0-9_-]{43}$/.test(id)) {
          this.validationError = 'TX ID must be exactly 43 characters (base64url)';
          return false;
        }
        this.validationError = '';
        return true;
      },

      promptBlock() {
        if (!this.validateTxId()) return;
        this.confirmDialog = {
          show: true,
          txId: this.txId.trim(),
          reason: this.reason.trim()
        };
      },

      async executeBlock() {
        this.loading = true;
        this.error = '';
        try {
          var resp = await api('/api/admin/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              tx_id: this.confirmDialog.txId,
              reason: this.confirmDialog.reason
            })
          });
          if (!resp.ok) {
            var errData = await resp.json().catch(function () { return {}; });
            throw new Error(errData.detail || 'Request failed (HTTP ' + resp.status + ')');
          }
          var result = await resp.json();
          this.confirmDialog.show = false;

          this.recentBlocks.unshift({
            tx_id: result.tx_id,
            reason: this.confirmDialog.reason,
            blocked: result.blocked,
            already_existed: result.already_existed,
            time: new Date().toLocaleString()
          });

          var msg = result.blocked
            ? 'Transaction blocked successfully'
            : 'Verdict saved but gateway block failed';
          var type = result.blocked ? 'success' : 'error';
          if (result.already_existed) {
            msg += ' (overwrote existing verdict)';
          }
          Alpine.store('toast').show(msg, type);

          this.txId = '';
          this.reason = '';
        } catch (e) {
          this.error = e.message || 'Failed to block transaction';
          Alpine.store('toast').show('Block failed: ' + (e.message || 'Unknown error'), 'error');
        }
        this.loading = false;
      }
    };
  });
});
