/**
 * BOLT12 Decoder Website - Interactive decoder using the bolt12 library.
 */

(function () {
  'use strict';

  // ---- TLV type metadata ----
  var TLV_INFO = {
    // Offer fields
    2:  { name: 'offer_chains',        color: 'var(--color-chains)',     decode: decodeChains },
    4:  { name: 'offer_metadata',      color: 'var(--color-metadata)',   decode: decodeHex },
    6:  { name: 'offer_currency',      color: 'var(--color-currency)',   decode: decodeUtf8 },
    8:  { name: 'offer_amount',        color: 'var(--color-amount)',     decode: decodeAmount },
    10: { name: 'offer_description',   color: 'var(--color-description)',decode: decodeUtf8 },
    12: { name: 'offer_features',      color: 'var(--color-features)',   decode: decodeFeatures },
    14: { name: 'offer_absolute_expiry', color: 'var(--color-expiry)',   decode: decodeExpiry },
    16: { name: 'offer_paths',         color: 'var(--color-paths)',      decode: decodePaths },
    18: { name: 'offer_issuer',        color: 'var(--color-issuer)',     decode: decodeUtf8 },
    20: { name: 'offer_quantity_max',  color: 'var(--color-quantity)',   decode: decodeQuantity },
    22: { name: 'offer_issuer_id',     color: 'var(--color-issuer-id)', decode: decodeHex },
    // Invoice request fields
    0:  { name: 'invreq_metadata',     color: 'var(--color-metadata)',   decode: decodeHex },
    32: { name: 'invreq_chain',        color: 'var(--color-chains)',     decode: decodeChains },
    34: { name: 'invreq_amount',       color: 'var(--color-amount)',     decode: decodeAmount },
    36: { name: 'invreq_features',     color: 'var(--color-features)',   decode: decodeFeatures },
    38: { name: 'invreq_quantity',     color: 'var(--color-quantity)',   decode: decodeQuantity },
    40: { name: 'invreq_payer_id',     color: 'var(--color-issuer-id)', decode: decodeHex },
    42: { name: 'invreq_payer_note',   color: 'var(--color-description)',decode: decodeUtf8 },
    // Invoice fields
    160: { name: 'invoice_paths',      color: 'var(--color-paths)',      decode: decodePaths },
    162: { name: 'invoice_blindedpay', color: 'var(--color-paths)',      decode: decodeHex },
    164: { name: 'invoice_created_at', color: 'var(--color-expiry)',     decode: decodeExpiry },
    166: { name: 'invoice_relative_expiry', color: 'var(--color-expiry)', decode: decodeAmount },
    168: { name: 'invoice_payment_hash', color: 'var(--color-metadata)', decode: decodeHex },
    170: { name: 'invoice_amount',     color: 'var(--color-amount)',     decode: decodeAmount },
    172: { name: 'invoice_fallbacks',  color: 'var(--color-paths)',      decode: decodeHex },
    174: { name: 'invoice_features',   color: 'var(--color-features)',   decode: decodeFeatures },
    176: { name: 'invoice_node_id',    color: 'var(--color-issuer-id)', decode: decodeHex },
    // Signature
    240: { name: 'signature',          color: 'var(--color-metadata)',   decode: decodeHex },
    // Payer proof fields (experimental, PR #1295)
    242: { name: 'proof_preimage',     color: 'var(--color-amount)',     decode: decodeHex },
    244: { name: 'proof_omitted_tlvs', color: 'var(--color-features)',   decode: decodeHex },
    246: { name: 'proof_missing_hashes', color: 'var(--color-paths)',    decode: decodeHex },
    248: { name: 'proof_leaf_hashes',  color: 'var(--color-chains)',     decode: decodeHex },
    250: { name: 'proof_payer_signature', color: 'var(--color-issuer-id)', decode: decodeHex },
  };

  // ---- Bech32 helpers ----
  var BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var BYTE_TO_BECH32 = {};
  // We pre-compute a reverse mapping isn't needed; we'll encode byte-by-byte via
  // the library's encodeBolt12 or do manual 5-bit conversion.

  // ---- Decode helpers ----
  function toHex(buf) {
    var hex = '';
    for (var i = 0; i < buf.length; i++) {
      hex += ('0' + buf[i].toString(16)).slice(-2);
    }
    return hex;
  }

  function readTruncatedUint(data) {
    if (data.length === 0) return 0;
    var val = 0n;
    for (var i = 0; i < data.length; i++) {
      val = (val << 8n) | BigInt(data[i]);
    }
    return val;
  }

  function decodeHex(value) {
    return toHex(value);
  }

  function decodeUtf8(value) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(value);
    } catch (e) {
      return toHex(value) + ' (invalid UTF-8)';
    }
  }

  function decodeAmount(value) {
    var v = readTruncatedUint(value);
    return v.toString() + ' msat';
  }

  function decodeExpiry(value) {
    var v = readTruncatedUint(value);
    try {
      return new Date(Number(v) * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
    } catch (e) {
      return v.toString();
    }
  }

  function decodeQuantity(value) {
    if (value.length === 0) return 'unlimited';
    var v = readTruncatedUint(value);
    return v.toString();
  }

  function decodeChains(value) {
    var chains = [];
    for (var i = 0; i < value.length; i += 32) {
      var hash = toHex(value.slice(i, i + 32));
      // Recognize known chains
      if (hash === '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000') {
        chains.push('bitcoin');
      } else if (hash === '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000') {
        chains.push('testnet');
      } else if (hash === '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003') {
        chains.push('liquidv1');
      } else {
        chains.push(hash.slice(0, 16) + '...');
      }
    }
    return chains.join(', ');
  }

  function decodeFeatures(value) {
    var bits = [];
    for (var byteIdx = 0; byteIdx < value.length; byteIdx++) {
      var b = value[byteIdx];
      if (b === 0) continue;
      var bitOffset = (value.length - 1 - byteIdx) * 8;
      for (var bit = 0; bit < 8; bit++) {
        if (b & (1 << bit)) {
          bits.push(bitOffset + bit);
        }
      }
    }
    if (bits.length === 0) return 'none';
    return 'bits: ' + bits.join(', ');
  }

  function decodePaths(value) {
    // Count paths
    var count = 0;
    var offset = 0;
    try {
      while (offset < value.length) {
        count++;
        var firstByte = value[offset];
        var firstNodeIdLen = (firstByte === 0x00 || firstByte === 0x01) ? 9 : 33;
        offset += firstNodeIdLen + 33; // first_node_id + path_key
        var numHops = value[offset]; offset++;
        for (var h = 0; h < numHops; h++) {
          offset += 33; // blinded_node_id
          var enclen = (value[offset] << 8) | value[offset + 1]; offset += 2;
          offset += enclen;
        }
      }
    } catch (e) {
      // ignore parse errors in display
    }
    return count + ' blinded path' + (count !== 1 ? 's' : '');
  }

  // ---- Convert bytes back to bech32 characters (for display mapping) ----
  function convertBits(data, fromBits, toBits) {
    var value = 0, bits = 0, maxV = (1 << toBits) - 1;
    var result = [];
    for (var i = 0; i < data.length; i++) {
      value = (value << fromBits) | data[i];
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        result.push((value >> bits) & maxV);
      }
    }
    if (bits > 0) {
      result.push((value << (toBits - bits)) & maxV);
    }
    return result;
  }

  // ---- Build a mapping: for each TLV record, which bech32 character indices it spans ----
  function buildCharRanges(records, dataBytes) {
    // First, figure out byte ranges for each TLV record in the data
    var byteRanges = [];
    var offset = 0;
    for (var i = 0; i < records.length; i++) {
      var rec = records[i];
      var startByte = offset;
      // BigSize for type
      var typeVal = Number(rec.type);
      if (typeVal < 0xfd) { offset += 1; }
      else if (typeVal <= 0xffff) { offset += 3; }
      else if (typeVal <= 0xffffffff) { offset += 5; }
      else { offset += 9; }
      // BigSize for length
      var lenVal = Number(rec.length);
      if (lenVal < 0xfd) { offset += 1; }
      else if (lenVal <= 0xffff) { offset += 3; }
      else if (lenVal <= 0xffffffff) { offset += 5; }
      else { offset += 9; }
      // value bytes
      offset += lenVal;
      byteRanges.push({ start: startByte, end: offset, record: rec });
    }

    // Now map byte positions to 5-bit group (bech32 char) positions
    // Each byte produces varying numbers of 5-bit groups.
    // The total bech32 chars = ceil(totalBytes * 8 / 5)
    var totalBytes = dataBytes.length;
    var totalChars = Math.ceil(totalBytes * 8 / 5);

    // For each bech32 char index, figure out which byte(s) it corresponds to
    // A bech32 char at index c covers bits [c*5, c*5+5) in the bitstream
    // A byte at index b covers bits [b*8, b*8+8) in the bitstream
    var charRanges = [];
    for (var r = 0; r < byteRanges.length; r++) {
      var range = byteRanges[r];
      var firstChar = Math.floor(range.start * 8 / 5);
      var lastChar = Math.ceil(range.end * 8 / 5) - 1;
      // Clamp
      if (lastChar >= totalChars) lastChar = totalChars - 1;
      charRanges.push({
        firstChar: firstChar,
        lastChar: lastChar,
        record: range.record
      });
    }
    return charRanges;
  }

  // ---- Main decode and render ----
  function decodeAndRender(input) {
    var display = document.getElementById('decoded-display');
    var infoPanel = document.getElementById('info-panel');
    var errorPanel = document.getElementById('error-panel');
    var fieldsTable = document.getElementById('fields-table');
    var fieldsTbody = document.getElementById('fields-tbody');

    // Reset
    errorPanel.style.display = 'none';
    errorPanel.textContent = '';
    fieldsTable.style.display = 'none';
    fieldsTbody.innerHTML = '';
    infoPanel.innerHTML = '<p class="info-placeholder">Hover over a highlighted section above to see more information.</p>';
    infoPanel.style.backgroundColor = '';

    if (!input || !input.trim()) {
      display.innerHTML = '<p class="placeholder-text">Paste a BOLT12 string (offer, invoice request, invoice, or payer proof) to decode it.</p>';
      return;
    }

    try {
      var decoded = bolt12.decodeBolt12(input.trim());
    } catch (e) {
      display.innerHTML = '<p class="placeholder-text">Paste a BOLT12 string (offer, invoice request, invoice, or payer proof) to decode it.</p>';
      errorPanel.style.display = 'block';
      errorPanel.textContent = 'Decode error: ' + e.message;
      return;
    }

    // Parse TLV
    var records;
    try {
      records = bolt12.parseTlvStream(decoded.data);
    } catch (e) {
      display.innerHTML = '<p class="placeholder-text">Paste a BOLT12 string (offer, invoice request, invoice, or payer proof) to decode it.</p>';
      errorPanel.style.display = 'block';
      errorPanel.textContent = 'TLV parse error: ' + e.message;
      return;
    }

    // Validate (but don't fail hard - still show what we can)
    var validationError = null;
    if (decoded.hrp === 'lno') {
      try {
        bolt12.validateOffer(records);
      } catch (e) {
        validationError = e.message;
      }
    } else if (decoded.hrp === 'lnp') {
      try {
        bolt12.parsePayerProof(records);
      } catch (e) {
        validationError = e.message;
      }
    }

    // Get the bech32 string (normalized lowercase)
    var bech32Str = input.trim().toLowerCase();
    // Find the data part (after the last '1')
    var sepIdx = bech32Str.lastIndexOf('1');
    var prefix = bech32Str.slice(0, sepIdx);
    var dataStr = bech32Str.slice(sepIdx + 1);

    // Build character ranges
    var charRanges = buildCharRanges(records, decoded.data);

    // Render the color-coded display
    var html = '';

    // Prefix part (e.g., "lno")
    html += '<span class="tlv-span" style="background:var(--color-issuer-id)" data-info-name="prefix" data-info-value="' + escapeAttr(prefix) + '">' + escapeHtml(prefix) + '</span>';
    html += '<span class="tlv-separator">1</span>';

    // Data part - color each character range
    var charToRecord = new Array(dataStr.length);
    for (var r = 0; r < charRanges.length; r++) {
      var cr = charRanges[r];
      for (var c = cr.firstChar; c <= cr.lastChar && c < dataStr.length; c++) {
        charToRecord[c] = cr.record;
      }
    }

    // Group consecutive chars with the same record
    var i = 0;
    while (i < dataStr.length) {
      var rec = charToRecord[i];
      var j = i;
      while (j < dataStr.length && charToRecord[j] === rec) j++;

      var chunk = dataStr.slice(i, j);
      if (rec) {
        var typeNum = Number(rec.type);
        var info = TLV_INFO[typeNum];
        var color = info ? info.color : 'var(--color-unknown)';
        var name = info ? info.name : 'unknown (type ' + typeNum + ')';
        var decodedVal = info ? info.decode(rec.value) : toHex(rec.value);

        html += '<span class="tlv-span" style="background:' + color + '"' +
          ' data-info-name="' + escapeAttr(name) + '"' +
          ' data-info-type="' + typeNum + '"' +
          ' data-info-length="' + Number(rec.length) + '"' +
          ' data-info-value="' + escapeAttr(decodedVal) + '"' +
          ' data-info-hex="' + escapeAttr(toHex(rec.value)) + '"' +
          ' data-info-color="' + color + '"' +
          '>' + escapeHtml(chunk) + '</span>';
      } else {
        // Padding bits at the end
        html += '<span class="tlv-separator">' + escapeHtml(chunk) + '</span>';
      }
      i = j;
    }

    display.innerHTML = html;

    // Show validation warning if any
    if (validationError) {
      errorPanel.style.display = 'block';
      errorPanel.textContent = 'Validation warning: ' + validationError;
    }

    // Populate fields table
    fieldsTable.style.display = 'block';
    for (var k = 0; k < records.length; k++) {
      var rec = records[k];
      var typeNum = Number(rec.type);
      var info = TLV_INFO[typeNum];
      var name = info ? info.name : 'unknown';
      var decodedVal = info ? info.decode(rec.value) : toHex(rec.value);

      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + typeNum + '</td>' +
        '<td>' + escapeHtml(name) + '</td>' +
        '<td>' + Number(rec.length) + '</td>' +
        '<td>' + escapeHtml(decodedVal) + '</td>';
      fieldsTbody.appendChild(tr);
    }

    // Wire up hover events
    var spans = display.querySelectorAll('.tlv-span[data-info-name]');
    for (var s = 0; s < spans.length; s++) {
      spans[s].addEventListener('mouseenter', onSpanHover);
      spans[s].addEventListener('mouseleave', onSpanLeave);
    }
  }

  function onSpanHover(e) {
    var el = e.currentTarget;
    var infoPanel = document.getElementById('info-panel');
    var name = el.getAttribute('data-info-name');
    var type = el.getAttribute('data-info-type');
    var length = el.getAttribute('data-info-length');
    var value = el.getAttribute('data-info-value');
    var hex = el.getAttribute('data-info-hex');
    var color = el.getAttribute('data-info-color');

    var html = '<div class="info-name">' + escapeHtml(name) + '</div>';
    if (type) {
      html += '<div><span class="info-label">Type</span> <span class="info-value">' + escapeHtml(type) + '</span></div>';
    }
    if (length) {
      html += '<div><span class="info-label">Length</span> <span class="info-value">' + escapeHtml(length) + ' bytes</span></div>';
    }
    if (value) {
      html += '<div><span class="info-label">Decoded</span> <span class="info-value">' + escapeHtml(value) + '</span></div>';
    }
    if (hex && hex !== value) {
      html += '<div><span class="info-label">Hex</span> <span class="info-value">' + escapeHtml(hex) + '</span></div>';
    }

    infoPanel.innerHTML = html;
    if (color) {
      infoPanel.style.backgroundColor = color;
    }
  }

  function onSpanLeave() {
    var infoPanel = document.getElementById('info-panel');
    infoPanel.innerHTML = '<p class="info-placeholder">Hover over a highlighted section above to see more information.</p>';
    infoPanel.style.backgroundColor = '';
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ---- Init ----
  var input = document.getElementById('bolt12-input');

  // Default sample offer
  var SAMPLE_OFFER = 'lno1pgx9getnwss8vetrw3hhyucjy358garswvaz7tmzdak8gvfj9ehhyeeqgf85c4p3xgsxjmnyw4ehgunfv4e3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs';
  input.value = SAMPLE_OFFER;

  // Debounce decode on input
  var timer = null;
  input.addEventListener('input', function () {
    clearTimeout(timer);
    timer = setTimeout(function () {
      decodeAndRender(input.value);
    }, 150);
  });

  // Initial decode
  decodeAndRender(SAMPLE_OFFER);
})();
