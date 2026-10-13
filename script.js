/**
 * ============================================================================
 * CLASSICAL CRYPTOGRAPHY TOOLKIT
 * Final Year Network Security Mini Project (2026–2027)
 * Complete Client-Side Mathematical Cryptographic Sandbox
 * ============================================================================
 */

(function () {
  'use strict';

  /* --------------------------------------------------------------------------
     1. MATHEMATICAL HELPER UTILITIES
     -------------------------------------------------------------------------- */

  /**
   * Positive modulo arithmetic (handles negative integers correctly)
   * (n mod m) in range [0, m - 1]
   */
  function mod(n, m) {
    return ((n % m) + m) % m;
  }

  /**
   * Greatest Common Divisor using Euclidean Algorithm
   */
  function gcd(a, b) {
    a = Math.abs(a);
    b = Math.abs(b);
    while (b) {
      const t = b;
      b = a % b;
      a = t;
    }
    return a;
  }

  /**
   * Extended Euclidean Algorithm to calculate modular multiplicative inverse
   * Returns x such that (a * x) mod m === 1, or null if no inverse exists
   */
  function modInverse(a, m) {
    a = mod(a, m);
    if (gcd(a, m) !== 1) return null;

    let [m0, x0, x1] = [m, 0, 1];
    let aVal = a;

    while (aVal > 1) {
      const q = Math.floor(aVal / m0);
      let t = m0;
      m0 = aVal % m0;
      aVal = t;

      t = x0;
      x0 = x1 - q * x0;
      x1 = t;
    }

    if (x1 < 0) x1 += m;
    return x1;
  }

  /**
   * Check if character is an English letter (A-Z or a-z)
   */
  function isAlpha(ch) {
    return /^[a-zA-Z]$/.test(ch);
  }

  /**
   * Check if character is uppercase
   */
  function isUpperCase(ch) {
    return ch >= 'A' && ch <= 'Z';
  }

  /**
   * Generate cryptographically secure random integer in [min, max]
   */
  function secureRandomInt(min, max) {
    const range = max - min + 1;
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return min + (array[0] % range);
  }

  /**
   * Generate cryptographically secure random permutation of 26 letters (A-Z)
   * Using Fisher-Yates shuffle with crypto.getRandomValues
   */
  function generateRandomAlphabet() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
    const randomBuffer = new Uint32Array(letters.length);
    window.crypto.getRandomValues(randomBuffer);

    for (let i = letters.length - 1; i > 0; i--) {
      const j = randomBuffer[i] % (i + 1);
      const temp = letters[i];
      letters[i] = letters[j];
      letters[j] = temp;
    }
    return letters.join('');
  }

  /**
   * Generate random uppercase key of specified length
   */
  function generateRandomKeyString(length) {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const buffer = new Uint32Array(length);
    window.crypto.getRandomValues(buffer);
    let result = '';
    for (let i = 0; i < length; i++) {
      result += letters[buffer[i] % 26];
    }
    return result;
  }


  /* --------------------------------------------------------------------------
     2. ALGORITHM ENGINES & IMPLEMENTATIONS
     -------------------------------------------------------------------------- */

  const CIPHER_REGISTRY = window.CIPHER_REGISTRY = {

    /* ------------------------------------------------------------------------
       2.1 CAESAR CIPHER
       E(x) = (x + k) mod 26
       D(x) = (x - k + 26) mod 26
       ------------------------------------------------------------------------ */
    caesar: {
      id: 'caesar',
      name: 'Caesar Cipher',
      family: 'substitution',
      categoryLabel: 'Monoalphabetic Substitution',
      mathFormula: 'C = (P + k) mod 26',
      description: 'A foundational symmetric shift cipher. Every letter is shifted down the alphabet by a fixed integer key.',
      rules: [
        'Preserves letter casing, whitespace, and punctuation',
        'Normalizes negative and large integer shift keys modulo 26',
        'Keyspace: 25 non-trivial shifts (1 to 25)'
      ],
      sampleTestVector: {
        plaintext: 'NETWORK SECURITY',
        key: '5',
        expectedCipher: 'SJYBTWP XJHZWNYD'
      },
      defaultKey: '5',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="caesarShiftInput">Shift Key (Integer k):</label>
            <input type="number" id="caesarShiftInput" class="form-input key-input" value="5" step="1" placeholder="e.g. 3 or 5">
          </div>
        `;
        const input = container.querySelector('#caesarShiftInput');
        input.addEventListener('input', onChange);
      },

      getKeyValue: function () {
        const input = document.getElementById('caesarShiftInput');
        return input ? input.value.trim() : '5';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('caesarShiftInput');
        if (input) input.value = val;
      },

      validateKey: function (keyVal) {
        if (keyVal === '' || keyVal === null || keyVal === undefined) {
          return { valid: false, error: 'Shift key cannot be empty. Please enter an integer.' };
        }
        const parsed = parseInt(keyVal, 10);
        if (isNaN(parsed)) {
          return { valid: false, error: 'Shift key must be a valid integer.' };
        }
        const normalized = mod(parsed, 26);
        let note = `Effective shift modulo 26 is ${normalized}.`;
        if (normalized === 0) {
          note += ' (Shift 0 will leave text unchanged)';
        }
        return { valid: true, normalizedKey: parsed, message: note };
      },

      encrypt: function (plaintext, keyVal) {
        const k = mod(parseInt(keyVal, 10), 26);
        let result = '';
        const trace = [];

        for (let i = 0; i < plaintext.length; i++) {
          const ch = plaintext[i];
          if (isAlpha(ch)) {
            const base = isUpperCase(ch) ? 65 : 97;
            const pVal = ch.charCodeAt(0) - base;
            const cVal = (pVal + k) % 26;
            const cChar = String.fromCharCode(base + cVal);
            result += cChar;
            if (trace.length < 15) {
              trace.push(`Char '${ch}' (${pVal}) -> (${pVal} + ${k}) mod 26 = ${cVal} -> '${cChar}'`);
            }
          } else {
            result += ch;
          }
        }
        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const k = mod(parseInt(keyVal, 10), 26);
        let result = '';
        const trace = [];

        for (let i = 0; i < ciphertext.length; i++) {
          const ch = ciphertext[i];
          if (isAlpha(ch)) {
            const base = isUpperCase(ch) ? 65 : 97;
            const cVal = ch.charCodeAt(0) - base;
            const pVal = mod(cVal - k, 26);
            const pChar = String.fromCharCode(base + pVal);
            result += pChar;
            if (trace.length < 15) {
              trace.push(`Char '${ch}' (${cVal}) -> (${cVal} - ${k} + 26) mod 26 = ${pVal} -> '${pChar}'`);
            }
          } else {
            result += ch;
          }
        }
        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.2 MONOALPHABETIC SUBSTITUTION CIPHER
       General 26-letter substitution alphabet
       ------------------------------------------------------------------------ */
    monoalphabetic: {
      id: 'monoalphabetic',
      name: 'Monoalphabetic Substitution Cipher',
      family: 'substitution',
      categoryLabel: 'Arbitrary Permutation Substitution',
      mathFormula: 'Permutation Mapping: f: A-Z → Key[0-25]',
      description: 'Replaces each English letter with a fixed arbitrary counterpart from a 26-character shuffled alphabet key.',
      rules: [
        'Key must contain exactly 26 distinct English letters (A-Z)',
        'Preserves character case, spaces, and punctuation',
        'Keyspace: 26! ≈ 4.03 × 10²⁶ possibilities'
      ],
      sampleTestVector: {
        plaintext: 'ATTACK AT ONCE',
        key: 'QWERTYUIOPASDFGHJKLZXCVBNM',
        expectedCipher: 'QZZQEA QZ GFTE'
      },
      defaultKey: 'QWERTYUIOPASDFGHJKLZXCVBNM',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="monoKeyInput">26-Letter Substitution Alphabet (A-Z mapped to Key[0-25]):</label>
            <input type="text" id="monoKeyInput" class="form-input key-input" value="QWERTYUIOPASDFGHJKLZXCVBNM" maxlength="26" placeholder="26 distinct English letters">
          </div>
        `;
        const input = container.querySelector('#monoKeyInput');
        input.addEventListener('input', onChange);
      },

      renderHeaderActions: function (container, onKeyUpdate) {
        container.innerHTML = `
          <button class="btn btn-sm btn-outline" id="generateMonoKeyBtn" title="Generate cryptographically random 26-letter key">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            Generate Random Key
          </button>
        `;
        const btn = container.querySelector('#generateMonoKeyBtn');
        btn.addEventListener('click', () => {
          const randKey = generateRandomAlphabet();
          const input = document.getElementById('monoKeyInput');
          if (input) {
            input.value = randKey;
            onKeyUpdate();
          }
        });
      },

      getKeyValue: function () {
        const input = document.getElementById('monoKeyInput');
        return input ? input.value.trim().toUpperCase() : 'QWERTYUIOPASDFGHJKLZXCVBNM';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('monoKeyInput');
        if (input) input.value = val.toUpperCase();
      },

      validateKey: function (keyVal) {
        if (!keyVal) {
          return { valid: false, error: 'Substitution key cannot be empty. 26 letters required.' };
        }
        const cleaned = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length !== 26) {
          return { valid: false, error: `Key must have exactly 26 letters. Currently contains ${cleaned.length}.` };
        }
        const set = new Set(cleaned.split(''));
        if (set.size !== 26) {
          return { valid: false, error: 'Key contains duplicate letters. All 26 letters must be unique.' };
        }
        return { valid: true, normalizedKey: cleaned, message: 'Valid 26-letter permutation key verified.' };
      },

      encrypt: function (plaintext, keyVal) {
        const key = keyVal.toUpperCase();
        let result = '';
        const trace = [];

        for (let i = 0; i < plaintext.length; i++) {
          const ch = plaintext[i];
          if (isAlpha(ch)) {
            const isUpper = isUpperCase(ch);
            const idx = ch.toUpperCase().charCodeAt(0) - 65;
            const subChar = key[idx];
            const finalChar = isUpper ? subChar : subChar.toLowerCase();
            result += finalChar;
            if (trace.length < 15) {
              trace.push(`Letter '${ch}' (${idx}) mapped to key[${idx}] -> '${finalChar}'`);
            }
          } else {
            result += ch;
          }
        }
        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const key = keyVal.toUpperCase();
        // Precompute inverse mapping
        const invMap = {};
        for (let i = 0; i < 26; i++) {
          invMap[key[i]] = String.fromCharCode(65 + i);
        }

        let result = '';
        const trace = [];

        for (let i = 0; i < ciphertext.length; i++) {
          const ch = ciphertext[i];
          if (isAlpha(ch)) {
            const isUpper = isUpperCase(ch);
            const plainUpper = invMap[ch.toUpperCase()];
            const finalChar = isUpper ? plainUpper : plainUpper.toLowerCase();
            result += finalChar;
            if (trace.length < 15) {
              trace.push(`Cipher '${ch}' reversed using key mapping -> '${finalChar}'`);
            }
          } else {
            result += ch;
          }
        }
        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.3 PLAYFAIR CIPHER
       5x5 matrix digraphic substitution (I and J combined)
       ------------------------------------------------------------------------ */
    playfair: {
      id: 'playfair',
      name: 'Playfair Cipher',
      family: 'substitution',
      categoryLabel: 'Digraphic Polygraphic Substitution',
      mathFormula: '5×5 Matrix Geometric Rules: Row / Column / Rectangle',
      description: 'Encrypts letter pairs (digraphs) across an interactive 5×5 key matrix with combined I/J cell.',
      rules: [
        'Matrix combines I and J into a single cell',
        'Duplicate letters within a digraph are separated with filler "X"',
        'Odd-length messages are padded with trailing "X"',
        'Text normalized to uppercase alphabetic letters'
      ],
      sampleTestVector: {
        plaintext: 'INSTRUMENTS',
        key: 'MONARCHY',
        expectedCipher: 'GATLMZCLRQXA'
      },
      defaultKey: 'MONARCHY',

      // Helper to build 5x5 matrix
      buildMatrix: function (keyword) {
        const cleaned = (keyword || '').toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
        const seen = new Set();
        const matrix = [];

        for (let i = 0; i < cleaned.length; i++) {
          const ch = cleaned[i];
          if (!seen.has(ch)) {
            seen.add(ch);
            matrix.push(ch);
          }
        }

        const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // J omitted
        for (let i = 0; i < alphabet.length; i++) {
          const ch = alphabet[i];
          if (!seen.has(ch)) {
            seen.add(ch);
            matrix.push(ch);
          }
        }

        // Return flat 25 array and lookup maps
        const posMap = {};
        for (let idx = 0; idx < 25; idx++) {
          const ch = matrix[idx];
          const row = Math.floor(idx / 5);
          const col = idx % 5;
          posMap[ch] = { row, col, index: idx };
        }

        return { grid: matrix, posMap };
      },

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="playfairKeywordInput">Keyword (for 5×5 Matrix Generation):</label>
            <input type="text" id="playfairKeywordInput" class="form-input key-input" value="MONARCHY" placeholder="e.g. MONARCHY or KEYWORD">
          </div>
        `;
        const input = container.querySelector('#playfairKeywordInput');
        input.addEventListener('input', onChange);
      },

      renderVisualizer: function (container, keyVal) {
        const matrixObj = CIPHER_REGISTRY.playfair.buildMatrix(keyVal);
        let cellsHtml = '';
        for (let i = 0; i < 25; i++) {
          const letter = matrixObj.grid[i];
          const displayLabel = letter === 'I' ? 'I/J' : letter;
          cellsHtml += `<div class="matrix-cell" title="Pos (${Math.floor(i/5)}, ${i%5})">${displayLabel}</div>`;
        }

        container.innerHTML = `
          <div class="visualizer-title">Generated 5×5 Playfair Key Matrix:</div>
          <div class="matrix-grid-5x5">${cellsHtml}</div>
        `;
        container.classList.add('active');
      },

      getKeyValue: function () {
        const input = document.getElementById('playfairKeywordInput');
        return input ? input.value.trim().toUpperCase() : 'MONARCHY';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('playfairKeywordInput');
        if (input) input.value = val.toUpperCase();
      },

      validateKey: function (keyVal) {
        if (!keyVal || keyVal.trim() === '') {
          return { valid: false, error: 'Playfair keyword cannot be empty. Please enter an alphabetic keyword.' };
        }
        const cleaned = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length === 0) {
          return { valid: false, error: 'Keyword must contain at least one English letter.' };
        }
        return { valid: true, normalizedKey: cleaned, message: `Keyword parsed: "${cleaned}" (I/J merged).` };
      },

      // Helper to prepare plaintext into digraphs
      prepareDigraphs: function (text) {
        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
        const digraphs = [];
        let i = 0;

        while (i < cleaned.length) {
          const a = cleaned[i];
          if (i + 1 < cleaned.length) {
            const b = cleaned[i + 1];
            if (a === b) {
              digraphs.push([a, 'X']);
              i++;
            } else {
              digraphs.push([a, b]);
              i += 2;
            }
          } else {
            // Last trailing character
            digraphs.push([a, 'X']);
            i++;
          }
        }
        return digraphs;
      },

      encrypt: function (plaintext, keyVal) {
        const matrixObj = CIPHER_REGISTRY.playfair.buildMatrix(keyVal);
        const { grid, posMap } = matrixObj;
        const digraphs = CIPHER_REGISTRY.playfair.prepareDigraphs(plaintext);
        let result = '';
        const trace = [];

        digraphs.forEach(([a, b]) => {
          const p1 = posMap[a];
          const p2 = posMap[b];
          let c1, c2, rule;

          if (p1.row === p2.row) {
            // Same row: shift right circularly
            c1 = grid[p1.row * 5 + (p1.col + 1) % 5];
            c2 = grid[p2.row * 5 + (p2.col + 1) % 5];
            rule = 'Same Row (Shift Right)';
          } else if (p1.col === p2.col) {
            // Same col: shift down circularly
            c1 = grid[((p1.row + 1) % 5) * 5 + p1.col];
            c2 = grid[((p2.row + 1) % 5) * 5 + p2.col];
            rule = 'Same Column (Shift Down)';
          } else {
            // Rectangle: swap columns
            c1 = grid[p1.row * 5 + p2.col];
            c2 = grid[p2.row * 5 + p1.col];
            rule = 'Rectangle (Swap Columns)';
          }

          result += c1 + c2;
          if (trace.length < 15) {
            trace.push(`Digraph [${a}${b}] -> [${c1}${c2}] via ${rule}`);
          }
        });

        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const matrixObj = CIPHER_REGISTRY.playfair.buildMatrix(keyVal);
        const { grid, posMap } = matrixObj;
        const cleaned = ciphertext.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
        let result = '';
        const trace = [];

        for (let i = 0; i < cleaned.length; i += 2) {
          const a = cleaned[i];
          const b = (i + 1 < cleaned.length) ? cleaned[i + 1] : 'X';
          const p1 = posMap[a] || posMap['X'];
          const p2 = posMap[b] || posMap['X'];
          let d1, d2, rule;

          if (p1.row === p2.row) {
            // Same row: shift left circularly
            d1 = grid[p1.row * 5 + mod(p1.col - 1, 5)];
            d2 = grid[p2.row * 5 + mod(p2.col - 1, 5)];
            rule = 'Same Row (Shift Left)';
          } else if (p1.col === p2.col) {
            // Same column: shift up circularly
            d1 = grid[mod(p1.row - 1, 5) * 5 + p1.col];
            d2 = grid[mod(p2.row - 1, 5) * 5 + p2.col];
            rule = 'Same Column (Shift Up)';
          } else {
            // Rectangle: swap columns
            d1 = grid[p1.row * 5 + p2.col];
            d2 = grid[p2.row * 5 + p1.col];
            rule = 'Rectangle (Swap Columns)';
          }

          result += d1 + d2;
          if (trace.length < 15) {
            trace.push(`Digraph [${a}${b}] -> [${d1}${d2}] via ${rule}`);
          }
        }

        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.4 HILL CIPHER (2×2 Matrix Inversion)
       C = (K × P) mod 26
       P = (K⁻¹ × C) mod 26
       ------------------------------------------------------------------------ */
    hill: {
      id: 'hill',
      name: 'Hill Cipher',
      family: 'substitution',
      categoryLabel: 'Polygraphic Linear Algebra (2×2 Matrix)',
      mathFormula: 'C = (K × P) mod 26  |  P = (K⁻¹ × C) mod 26',
      description: 'Treats letter blocks as column vectors in GF(26) multiplied by an invertible 2×2 modular integer matrix.',
      rules: [
        'Requires 2×2 integer matrix with gcd(det(K), 26) = 1',
        'Determinant must be coprime to 26 (not divisible by 2 or 13)',
        'Odd plaintext length automatically padded with "X"',
        'Letters indexed as A = 0 through Z = 25'
      ],
      sampleTestVector: {
        plaintext: 'HELP',
        key: '3,3,2,5',
        expectedCipher: 'HIAT'
      },
      defaultKey: '3,3,2,5',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label>2×2 Encryption Matrix K = [[k00, k01], [k10, k11]]:</label>
            <div class="hill-matrix-inputs">
              <input type="number" id="hillK00" class="form-input key-input hill-cell-input" value="3" placeholder="k00">
              <input type="number" id="hillK01" class="form-input key-input hill-cell-input" value="3" placeholder="k01">
              <input type="number" id="hillK10" class="form-input key-input hill-cell-input" value="2" placeholder="k10">
              <input type="number" id="hillK11" class="form-input key-input hill-cell-input" value="5" placeholder="k11">
            </div>
          </div>
        `;
        const inputs = container.querySelectorAll('.hill-cell-input');
        inputs.forEach(inp => inp.addEventListener('input', onChange));
      },

      renderVisualizer: function (container, keyVal) {
        const matrix = CIPHER_REGISTRY.hill.parseMatrix(keyVal);
        if (!matrix) return;
        const det = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
        const detMod = mod(det, 26);
        const invDet = modInverse(detMod, 26);

        if (invDet === null) {
          container.innerHTML = `
            <div class="validation-message error" style="display:flex;">
              Matrix Determinant is ${det} (≡ ${detMod} mod 26). gcd(${detMod}, 26) = ${gcd(detMod, 26)} ≠ 1.
              Matrix is NON-INVERTIBLE modulo 26!
            </div>
          `;
          container.classList.add('active');
          return;
        }

        const inv00 = mod(matrix[1][1] * invDet, 26);
        const inv01 = mod(-matrix[0][1] * invDet, 26);
        const inv10 = mod(-matrix[1][0] * invDet, 26);
        const inv11 = mod(matrix[0][0] * invDet, 26);

        container.innerHTML = `
          <div class="visualizer-title">Modular Matrix Inversion Breakdown:</div>
          <div class="hill-calc-summary">
            <div class="hill-calc-item">Determinant: <span>${det} ≡ ${detMod} mod 26</span></div>
            <div class="hill-calc-item">Det Inverse: <span>${invDet}</span></div>
            <div class="hill-calc-item">Inverse Matrix K⁻¹: <span>[[${inv00}, ${inv01}], [${inv10}, ${inv11}]] mod 26</span></div>
          </div>
        `;
        container.classList.add('active');
      },

      parseMatrix: function (keyVal) {
        if (!keyVal) return null;
        const parts = keyVal.split(',').map(s => parseInt(s.trim(), 10));
        if (parts.length !== 4 || parts.some(isNaN)) return null;
        return [
          [parts[0], parts[1]],
          [parts[2], parts[3]]
        ];
      },

      getKeyValue: function () {
        const k00 = document.getElementById('hillK00');
        const k01 = document.getElementById('hillK01');
        const k10 = document.getElementById('hillK10');
        const k11 = document.getElementById('hillK11');
        if (k00 && k01 && k10 && k11) {
          return `${k00.value.trim()},${k01.value.trim()},${k10.value.trim()},${k11.value.trim()}`;
        }
        return '3,3,2,5';
      },

      setKeyValue: function (val) {
        const parts = (val || '3,3,2,5').split(',');
        if (parts.length === 4) {
          ['hillK00', 'hillK01', 'hillK10', 'hillK11'].forEach((id, idx) => {
            const el = document.getElementById(id);
            if (el) el.value = parts[idx];
          });
        }
      },

      validateKey: function (keyVal) {
        const matrix = CIPHER_REGISTRY.hill.parseMatrix(keyVal);
        if (!matrix) {
          return { valid: false, error: 'Please enter 4 valid integer elements for the 2×2 matrix.' };
        }
        const det = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
        const detMod = mod(det, 26);
        const dGcd = gcd(detMod, 26);

        if (dGcd !== 1) {
          return {
            valid: false,
            error: `Matrix determinant det(K) = ${det} ≡ ${detMod} (mod 26). gcd(${detMod}, 26) = ${dGcd} ≠ 1. Non-invertible!`
          };
        }
        const invDet = modInverse(detMod, 26);
        return {
          valid: true,
          normalizedKey: keyVal,
          message: `Invertible! det ≡ ${detMod}, det⁻¹ ≡ ${invDet} (mod 26).`
        };
      },

      encrypt: function (plaintext, keyVal) {
        const matrix = CIPHER_REGISTRY.hill.parseMatrix(keyVal);
        const k00 = matrix[0][0];
        const k01 = matrix[0][1];
        const k10 = matrix[1][0];
        const k11 = matrix[1][1];

        let cleaned = plaintext.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length % 2 !== 0) {
          cleaned += 'X'; // Pad odd length with X
        }

        let result = '';
        const trace = [];

        for (let i = 0; i < cleaned.length; i += 2) {
          const p0 = cleaned.charCodeAt(i) - 65;
          const p1 = cleaned.charCodeAt(i + 1) - 65;

          const c0 = mod(k00 * p0 + k01 * p1, 26);
          const c1 = mod(k10 * p0 + k11 * p1, 26);

          const ch0 = String.fromCharCode(65 + c0);
          const ch1 = String.fromCharCode(65 + c1);

          result += ch0 + ch1;
          if (trace.length < 15) {
            trace.push(`Vector [${p0}, ${p1}]^T ('${cleaned[i]}${cleaned[i+1]}') × K mod 26 -> [${c0}, ${c1}]^T ('${ch0}${ch1}')`);
          }
        }

        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const matrix = CIPHER_REGISTRY.hill.parseMatrix(keyVal);
        const det = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
        const detMod = mod(det, 26);
        const invDet = modInverse(detMod, 26);

        // Compute inverse matrix mod 26
        const inv00 = mod(matrix[1][1] * invDet, 26);
        const inv01 = mod(-matrix[0][1] * invDet, 26);
        const inv10 = mod(-matrix[1][0] * invDet, 26);
        const inv11 = mod(matrix[0][0] * invDet, 26);

        let cleaned = ciphertext.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length % 2 !== 0) {
          cleaned += 'X';
        }

        let result = '';
        const trace = [];

        for (let i = 0; i < cleaned.length; i += 2) {
          const c0 = cleaned.charCodeAt(i) - 65;
          const c1 = cleaned.charCodeAt(i + 1) - 65;

          const p0 = mod(inv00 * c0 + inv01 * c1, 26);
          const p1 = mod(inv10 * c0 + inv11 * c1, 26);

          const ch0 = String.fromCharCode(65 + p0);
          const ch1 = String.fromCharCode(65 + p1);

          result += ch0 + ch1;
          if (trace.length < 15) {
            trace.push(`Vector [${c0}, ${c1}]^T ('${cleaned[i]}${cleaned[i+1]}') × K⁻¹ mod 26 -> [${p0}, ${p1}]^T ('${ch0}${ch1}')`);
          }
        }

        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.5 VIGENÈRE CIPHER
       C_i = (P_i + K_i) mod 26
       P_i = (C_i - K_i + 26) mod 26
       ------------------------------------------------------------------------ */
    vigenere: {
      id: 'vigenere',
      name: 'Vigenère Cipher',
      family: 'substitution',
      categoryLabel: 'Polyalphabetic Periodic Shift',
      mathFormula: 'Cᵢ = (Pᵢ + Kᵢ) mod 26  |  Pᵢ = (Cᵢ - Kᵢ + 26) mod 26',
      description: 'Polyalphabetic cipher using repeated keyword characters as sequential Caesar shifts.',
      rules: [
        'Keyword advances only over alphabetic characters',
        'Preserves original case, spaces, digits, and punctuation',
        'Historically considered unbreakable until Kasiski & Friedman cryptanalysis'
      ],
      sampleTestVector: {
        plaintext: 'ATTACKATDAWN',
        key: 'LEMON',
        expectedCipher: 'LXFOPVEFRNHR'
      },
      defaultKey: 'LEMON',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="vigenereKeywordInput">Alphabetic Keyword:</label>
            <input type="text" id="vigenereKeywordInput" class="form-input key-input" value="LEMON" placeholder="e.g. LEMON or CIPHER">
          </div>
        `;
        const input = container.querySelector('#vigenereKeywordInput');
        input.addEventListener('input', onChange);
      },

      getKeyValue: function () {
        const input = document.getElementById('vigenereKeywordInput');
        return input ? input.value.trim().toUpperCase() : 'LEMON';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('vigenereKeywordInput');
        if (input) input.value = val.toUpperCase();
      },

      validateKey: function (keyVal) {
        if (!keyVal || keyVal.trim() === '') {
          return { valid: false, error: 'Keyword cannot be empty. Please enter an alphabetic keyword.' };
        }
        const cleaned = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length === 0) {
          return { valid: false, error: 'Keyword must contain at least one English letter (A-Z).' };
        }
        return { valid: true, normalizedKey: cleaned, message: `Keyword length: ${cleaned.length} letters.` };
      },

      encrypt: function (plaintext, keyVal) {
        const key = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        let keyIdx = 0;
        let result = '';
        const trace = [];

        for (let i = 0; i < plaintext.length; i++) {
          const ch = plaintext[i];
          if (isAlpha(ch)) {
            const isUpper = isUpperCase(ch);
            const base = isUpper ? 65 : 97;
            const pVal = ch.charCodeAt(0) - base;
            const kChar = key[keyIdx % key.length];
            const kVal = kChar.charCodeAt(0) - 65;
            const cVal = (pVal + kVal) % 26;
            const cChar = String.fromCharCode(base + cVal);

            result += cChar;
            if (trace.length < 15) {
              trace.push(`'${ch}' (${pVal}) + Key '${kChar}' (${kVal}) mod 26 = ${cVal} -> '${cChar}'`);
            }
            keyIdx++;
          } else {
            result += ch;
          }
        }

        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const key = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        let keyIdx = 0;
        let result = '';
        const trace = [];

        for (let i = 0; i < ciphertext.length; i++) {
          const ch = ciphertext[i];
          if (isAlpha(ch)) {
            const isUpper = isUpperCase(ch);
            const base = isUpper ? 65 : 97;
            const cVal = ch.charCodeAt(0) - base;
            const kChar = key[keyIdx % key.length];
            const kVal = kChar.charCodeAt(0) - 65;
            const pVal = mod(cVal - kVal, 26);
            const pChar = String.fromCharCode(base + pVal);

            result += pChar;
            if (trace.length < 15) {
              trace.push(`'${ch}' (${cVal}) - Key '${kChar}' (${kVal}) + 26 mod 26 = ${pVal} -> '${pChar}'`);
            }
            keyIdx++;
          } else {
            result += ch;
          }
        }

        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.6 ONE-TIME PAD (VERNAM CIPHER)
       Key length >= normalized plaintext length
       ------------------------------------------------------------------------ */
    otp: {
      id: 'otp',
      name: 'One-Time Pad (Vernam Cipher)',
      family: 'substitution',
      categoryLabel: 'Information-Theoretic Perfect Secrecy',
      mathFormula: 'Cᵢ = (Pᵢ + Kᵢ) mod 26  |  Key Length = Plaintext Length',
      description: 'The only mathematically unbreakable cipher when used with a truly random, non-reused key of equal length.',
      rules: [
        'Key length must be equal to or greater than the alphabetic letter count of the message',
        'Demonstration key generated using browser window.crypto.getRandomValues',
        'Preserves letter case, punctuation, and whitespace',
        'Never reuse the key across messages (OTP security relies on single-use)'
      ],
      sampleTestVector: {
        plaintext: 'HELLO',
        key: 'XMCKL',
        expectedCipher: 'EQNVZ'
      },
      defaultKey: 'XMCKL',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="otpKeyInput">Alphabetic Key (Must match or exceed input letter count):</label>
            <input type="text" id="otpKeyInput" class="form-input key-input" value="XMCKL" placeholder="Random key of matching length">
          </div>
        `;
        const input = container.querySelector('#otpKeyInput');
        input.addEventListener('input', onChange);
      },

      renderHeaderActions: function (container, onKeyUpdate) {
        container.innerHTML = `
          <button class="btn btn-sm btn-outline" id="generateOtpKeyBtn" title="Generate random key matched to input message length">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            Generate Key for Input
          </button>
        `;
        const btn = container.querySelector('#generateOtpKeyBtn');
        btn.addEventListener('click', () => {
          const inputArea = document.getElementById('cryptoInputText');
          const text = inputArea ? inputArea.value : '';
          const alphaCount = (text.match(/[a-zA-Z]/g) || []).length;
          const targetLen = Math.max(alphaCount, 5);
          const newKey = generateRandomKeyString(targetLen);

          const keyInput = document.getElementById('otpKeyInput');
          if (keyInput) {
            keyInput.value = newKey;
            onKeyUpdate();
          }
        });
      },

      getKeyValue: function () {
        const input = document.getElementById('otpKeyInput');
        return input ? input.value.trim().toUpperCase() : 'XMCKL';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('otpKeyInput');
        if (input) input.value = val.toUpperCase();
      },

      validateKey: function (keyVal, contextText) {
        if (!keyVal || keyVal.trim() === '') {
          return { valid: false, error: 'One-Time Pad key cannot be empty.' };
        }
        const cleanedKey = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleanedKey.length === 0) {
          return { valid: false, error: 'Key must contain English letters.' };
        }

        if (contextText) {
          const alphaCount = (contextText.match(/[a-zA-Z]/g) || []).length;
          if (cleanedKey.length < alphaCount) {
            return {
              valid: false,
              error: `Key length (${cleanedKey.length}) is shorter than message letter count (${alphaCount}). One-Time Pad requires a full-length key!`
            };
          }
        }

        return {
          valid: true,
          normalizedKey: cleanedKey,
          message: `Key length: ${cleanedKey.length} letters available.`
        };
      },

      encrypt: function (plaintext, keyVal) {
        const key = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        let keyIdx = 0;
        let result = '';
        const trace = [];

        for (let i = 0; i < plaintext.length; i++) {
          const ch = plaintext[i];
          if (isAlpha(ch)) {
            const isUpper = isUpperCase(ch);
            const base = isUpper ? 65 : 97;
            const pVal = ch.charCodeAt(0) - base;
            const kChar = key[keyIdx];
            const kVal = kChar.charCodeAt(0) - 65;
            const cVal = (pVal + kVal) % 26;
            const cChar = String.fromCharCode(base + cVal);

            result += cChar;
            if (trace.length < 15) {
              trace.push(`'${ch}' (${pVal}) + Key[${keyIdx}] '${kChar}' (${kVal}) mod 26 = ${cVal} -> '${cChar}'`);
            }
            keyIdx++;
          } else {
            result += ch;
          }
        }

        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const key = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        let keyIdx = 0;
        let result = '';
        const trace = [];

        for (let i = 0; i < ciphertext.length; i++) {
          const ch = ciphertext[i];
          if (isAlpha(ch)) {
            const isUpper = isUpperCase(ch);
            const base = isUpper ? 65 : 97;
            const cVal = ch.charCodeAt(0) - base;
            const kChar = key[keyIdx];
            const kVal = kChar.charCodeAt(0) - 65;
            const pVal = mod(cVal - kVal, 26);
            const pChar = String.fromCharCode(base + pVal);

            result += pChar;
            if (trace.length < 15) {
              trace.push(`'${ch}' (${cVal}) - Key[${keyIdx}] '${kChar}' (${kVal}) + 26 mod 26 = ${pVal} -> '${pChar}'`);
            }
            keyIdx++;
          } else {
            result += ch;
          }
        }

        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.7 RAIL FENCE CIPHER (ZIGZAG TRANSPOSITION)
       ------------------------------------------------------------------------ */
    railfence: {
      id: 'railfence',
      name: 'Rail Fence Cipher',
      family: 'transposition',
      categoryLabel: 'Zigzag Permutation Transposition',
      mathFormula: 'Cycle Period = 2 × (rails - 1)',
      description: 'Arranges characters along a diagonal zigzag pattern across imaginary rails, then reads rows sequentially.',
      rules: [
        'Positive integer rail count r >= 1',
        'Preserves full character sequence including spaces and punctuation',
        'Letter frequencies remain 100% unaltered (vulnerable to frequency analysis)'
      ],
      sampleTestVector: {
        plaintext: 'WEAREDISCOVEREDFLEEATONCE',
        key: '3',
        expectedCipher: 'WECRLTEERDSOEEFEAOCAIVDEN'
      },
      defaultKey: '3',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="railFenceRailsInput">Number of Rails (Depth r ≥ 1):</label>
            <input type="number" id="railFenceRailsInput" class="form-input key-input" value="3" min="1" step="1" placeholder="e.g. 3">
          </div>
        `;
        const input = container.querySelector('#railFenceRailsInput');
        input.addEventListener('input', onChange);
      },

      renderVisualizer: function (container, keyVal) {
        const rails = parseInt(keyVal, 10);
        if (isNaN(rails) || rails < 1) return;
        const sampleText = 'CRYPTOGRAPHY';
        const displayLen = Math.min(sampleText.length, 14);
        const subText = sampleText.slice(0, displayLen);

        const grid = Array.from({ length: rails }, () => new Array(displayLen).fill('.'));
        let r = 0;
        let d = 1;
        for (let i = 0; i < displayLen; i++) {
          grid[r][i] = subText[i];
          if (rails > 1) {
            r += d;
            if (r === rails - 1) d = -1;
            else if (r === 0) d = 1;
          }
        }

        let preHtml = '';
        for (let row = 0; row < rails; row++) {
          preHtml += `Rail ${row + 1}:  ` + grid[row].map(ch => ch === '.' ? '·' : ch).join('  ') + '\n';
        }

        container.innerHTML = `
          <div class="visualizer-title">Rail Fence Zigzag Geometry Preview (Pattern for "${subText}"):</div>
          <pre style="background:var(--bg-surface);padding:10px 14px;border-radius:6px;font-family:var(--font-mono);color:var(--accent-cyan);overflow-x:auto;font-size:0.85rem;line-height:1.6;">${preHtml}</pre>
        `;
        container.classList.add('active');
      },

      getKeyValue: function () {
        const input = document.getElementById('railFenceRailsInput');
        return input ? input.value.trim() : '3';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('railFenceRailsInput');
        if (input) input.value = val;
      },

      validateKey: function (keyVal) {
        if (!keyVal || keyVal.trim() === '') {
          return { valid: false, error: 'Rail count cannot be empty. Positive integer required.' };
        }
        const rails = parseInt(keyVal, 10);
        if (isNaN(rails) || rails < 1) {
          return { valid: false, error: 'Rail count must be a positive integer greater than or equal to 1.' };
        }
        return { valid: true, normalizedKey: rails, message: `Configured with ${rails} rails.` };
      },

      encrypt: function (plaintext, keyVal) {
        const rails = parseInt(keyVal, 10);
        if (rails <= 1 || rails >= plaintext.length) {
          return { output: plaintext, trace: ['Rail count <= 1 or >= message length; output equals input.'] };
        }

        const fence = Array.from({ length: rails }, () => []);
        let rail = 0;
        let direction = 1;

        for (let i = 0; i < plaintext.length; i++) {
          fence[rail].push(plaintext[i]);
          rail += direction;
          if (rail === rails - 1) direction = -1;
          else if (rail === 0) direction = 1;
        }

        let result = '';
        const trace = [];
        for (let r = 0; r < rails; r++) {
          const rowStr = fence[r].join('');
          result += rowStr;
          trace.push(`Rail #${r + 1} (${fence[r].length} chars): "${rowStr}"`);
        }

        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const rails = parseInt(keyVal, 10);
        const len = ciphertext.length;
        if (rails <= 1 || rails >= len) {
          return { output: ciphertext, trace: ['Rail count <= 1 or >= message length; output equals input.'] };
        }

        // Determine number of characters in each rail
        const fenceCounts = new Array(rails).fill(0);
        let rail = 0;
        let direction = 1;

        for (let i = 0; i < len; i++) {
          fenceCounts[rail]++;
          rail += direction;
          if (rail === rails - 1) direction = -1;
          else if (rail === 0) direction = 1;
        }

        // Slice ciphertext into rail buckets
        const fenceRows = [];
        let cursor = 0;
        const trace = [];
        for (let r = 0; r < rails; r++) {
          const count = fenceCounts[r];
          fenceRows.push(ciphertext.slice(cursor, cursor + count).split(''));
          trace.push(`Reconstructed Rail #${r + 1}: ${fenceRows[r].join('')}`);
          cursor += count;
        }

        // Reconstruct zigzag order
        let result = '';
        rail = 0;
        direction = 1;
        for (let i = 0; i < len; i++) {
          result += fenceRows[rail].shift();
          rail += direction;
          if (rail === rails - 1) direction = -1;
          else if (rail === 0) direction = 1;
        }

        return { output: result, trace };
      }
    },


    /* ------------------------------------------------------------------------
       2.8 COLUMNAR TRANSPOSITION CIPHER
       Keyword grid with stable tie-breaking for repeated letters
       ------------------------------------------------------------------------ */
    columnar: {
      id: 'columnar',
      name: 'Columnar Transposition Cipher',
      family: 'transposition',
      categoryLabel: 'Permutation Matrix Transposition',
      mathFormula: 'Grid Dimension: ceil(Length / Key.Length)',
      description: 'Writes plaintext row-by-row into a grid and reads columns in alphabetical order of keyword letters.',
      rules: [
        'Alphabetic keyword determines column read sequence',
        'Duplicate letters resolved via stable alphabetical ordering with original index tie-breaker',
        'Incomplete grids padded with "X" to ensure complete invertible rectangular matrix'
      ],
      sampleTestVector: {
        plaintext: 'DEFENDTHEEASTWALL',
        key: 'GERMAN',
        expectedCipher: 'NALEHWDTTEELDSXFEA'
      },
      defaultKey: 'GERMAN',

      renderKeyControls: function (container, onChange) {
        container.innerHTML = `
          <div class="key-field-group">
            <label for="columnarKeywordInput">Alphabetic Keyword:</label>
            <input type="text" id="columnarKeywordInput" class="form-input key-input" value="GERMAN" placeholder="e.g. GERMAN or CIPHER">
          </div>
        `;
        const input = container.querySelector('#columnarKeywordInput');
        input.addEventListener('input', onChange);
      },

      renderVisualizer: function (container, keyVal) {
        if (!keyVal) return;
        const cleaned = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length === 0) return;
        const colOrder = CIPHER_REGISTRY.columnar.getColumnOrder(cleaned);

        const ranks = new Array(cleaned.length);
        colOrder.forEach((origCol, rankIdx) => {
          ranks[origCol] = rankIdx + 1;
        });

        let headerHtml = '';
        for (let i = 0; i < cleaned.length; i++) {
          headerHtml += `
            <div style="display:flex;flex-direction:column;align-items:center;background:var(--bg-surface);border:1px solid var(--border-medium);border-radius:4px;padding:6px 10px;min-width:38px;">
              <span style="font-size:0.75rem;color:var(--text-muted);">Col ${i + 1}</span>
              <strong style="color:var(--accent-cyan);font-size:1.1rem;font-family:var(--font-mono);">${cleaned[i]}</strong>
              <span style="font-size:0.7rem;color:var(--accent-emerald);font-weight:700;">Order: #${ranks[i]}</span>
            </div>
          `;
        }

        container.innerHTML = `
          <div class="visualizer-title">Keyword Column Reading Order & Tie-Breaking Breakdown:</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">${headerHtml}</div>
          <div style="font-size:0.75rem;color:var(--text-secondary);">
            Columns are extracted in sorted rank order: <strong>${colOrder.map(c => `Col ${c + 1} ('${cleaned[c]}')`).join(' → ')}</strong>
          </div>
        `;
        container.classList.add('active');
      },

      getKeyValue: function () {
        const input = document.getElementById('columnarKeywordInput');
        return input ? input.value.trim().toUpperCase() : 'GERMAN';
      },

      setKeyValue: function (val) {
        const input = document.getElementById('columnarKeywordInput');
        if (input) input.value = val.toUpperCase();
      },

      validateKey: function (keyVal) {
        if (!keyVal || keyVal.trim() === '') {
          return { valid: false, error: 'Keyword cannot be empty. Please enter an alphabetic keyword.' };
        }
        const cleaned = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        if (cleaned.length === 0) {
          return { valid: false, error: 'Keyword must contain at least one English letter (A-Z).' };
        }
        return { valid: true, normalizedKey: cleaned, message: `Keyword length: ${cleaned.length} columns.` };
      },

      // Calculate stable column reading order
      getColumnOrder: function (keyword) {
        const keyChars = keyword.split('').map((char, index) => ({ char, index }));
        // Sort by character, then by original column index
        keyChars.sort((a, b) => {
          if (a.char < b.char) return -1;
          if (a.char > b.char) return 1;
          return a.index - b.index;
        });
        return keyChars.map(item => item.index);
      },

      encrypt: function (plaintext, keyVal) {
        const key = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        const colCount = key.length;
        const colOrder = CIPHER_REGISTRY.columnar.getColumnOrder(key);

        let text = plaintext;
        // Pad with 'X' so length is multiple of colCount
        const padLen = (colCount - (text.length % colCount)) % colCount;
        if (padLen > 0) {
          text += 'X'.repeat(padLen);
        }

        const numRows = text.length / colCount;
        const grid = [];
        for (let r = 0; r < numRows; r++) {
          grid.push(text.slice(r * colCount, (r + 1) * colCount).split(''));
        }

        let result = '';
        const trace = [
          `Grid geometry: ${numRows} rows × ${colCount} cols. Padding added: ${padLen} chars ("X").`,
          `Column read order: ${colOrder.map(c => `Col ${c + 1} ('${key[c]}')`).join(' -> ')}`
        ];

        colOrder.forEach(colIdx => {
          let colText = '';
          for (let r = 0; r < numRows; r++) {
            colText += grid[r][colIdx];
          }
          result += colText;
          if (trace.length < 15) {
            trace.push(`Reading Col #${colIdx + 1} ('${key[colIdx]}'): "${colText}"`);
          }
        });

        return { output: result, trace };
      },

      decrypt: function (ciphertext, keyVal) {
        const key = keyVal.toUpperCase().replace(/[^A-Z]/g, '');
        const colCount = key.length;
        const colOrder = CIPHER_REGISTRY.columnar.getColumnOrder(key);

        const numRows = Math.ceil(ciphertext.length / colCount);
        const grid = Array.from({ length: numRows }, () => new Array(colCount).fill(''));

        let charIdx = 0;
        const trace = [
          `Reconstructing ${numRows} rows × ${colCount} columns from sorted key.`,
          `Column extraction sequence: ${colOrder.map(c => `Col ${c + 1}`).join(' -> ')}`
        ];

        // Fill columns in sorted order
        colOrder.forEach(colIdx => {
          for (let r = 0; r < numRows; r++) {
            if (charIdx < ciphertext.length) {
              grid[r][colIdx] = ciphertext[charIdx++];
            }
          }
        });

        // Read out row by row
        let result = '';
        for (let r = 0; r < numRows; r++) {
          const rowStr = grid[r].join('');
          result += rowStr;
          if (trace.length < 15) {
            trace.push(`Row #${r + 1}: "${rowStr}"`);
          }
        }

        return { output: result, trace };
      }
    }
  };


  /* --------------------------------------------------------------------------
     3. ALGORITHM COMPARISON MATRIX DATA
     -------------------------------------------------------------------------- */

  const COMPARISON_DATA = [
    {
      name: 'Caesar Cipher',
      type: 'Monoalphabetic Substitution',
      typeClass: 'sub',
      key: 'Single Integer (Shift 0–25)',
      working: 'Shifts each letter uniformly by a fixed constant integer k positions along the alphabet modulo 26.',
      advantages: 'Extremely simple to compute by hand or in hardware; zero key preparation time.',
      limitations: 'Negligible keyspace (25 non-trivial keys). Easily broken via manual brute-force or letter frequency in milliseconds.',
      security: 'Trivial / Zero Security. Broken via brute-force exhaust in 25 attempts.'
    },
    {
      name: 'Monoalphabetic Cipher',
      type: 'Monoalphabetic Substitution',
      typeClass: 'sub',
      key: '26-Letter Permutation Alphabet',
      working: 'Maps each letter of the alphabet to a unique counterpart from a 26-letter shuffled substitution key.',
      advantages: 'Astronomical keyspace of 26! ≈ 4.03 × 10²⁶ keys makes brute-force search computationally infeasible.',
      limitations: 'Single-letter frequency distribution is completely preserved. Instantly broken via frequency analysis.',
      security: 'Insecure. Vulnerable to unigram frequency counts (E, T, A, O, I, N).'
    },
    {
      name: 'Playfair Cipher',
      type: 'Digraphic Substitution',
      typeClass: 'sub',
      key: 'Keyword (5×5 Matrix, I/J merged)',
      working: 'Encrypts letter pairs (digraphs) using row, column, and rectangular coordinate transformations on a 5×5 grid.',
      advantages: 'Significantly flattens single-letter frequency distribution by operating across 600 possible digraphs.',
      limitations: 'Vulnerable to digraphic frequency analysis; inserts filler "X" padding; requires uppercase alphabetic normalization.',
      security: 'Weak. Historically broken by analyzing digraph frequency tables.'
    },
    {
      name: 'Hill Cipher',
      type: 'Polygraphic Substitution',
      typeClass: 'sub',
      key: '2×2 Modular Invertible Matrix',
      working: 'Treats letter pairs as column vectors in GF(26) and performs linear matrix multiplication mod 26.',
      advantages: 'Disguises both single-letter and digraph frequencies; applies linear algebraic diffusion across blocks.',
      limitations: 'Completely vulnerable to Known-Plaintext Attack (KPA). Two known digraph pairs reveal the key matrix in seconds.',
      security: 'Mathematically Linear. Insecure against known-plaintext cryptanalysis.'
    },
    {
      name: 'Vigenère Cipher',
      type: 'Polyalphabetic Substitution',
      typeClass: 'sub',
      key: 'Alphabetic Keyword',
      working: 'Applies multiple alternating Caesar shifts across the message governed cyclically by keyword characters.',
      advantages: 'Smooths out classical frequency peaks; was historically dubbed "le chiffre indéchiffrable" for 300 years.',
      limitations: 'Periodic key repetition creates statistical coincidences detectable via Kasiski examination and Index of Coincidence.',
      security: 'Moderate Historical. Broken once key length is determined via Kasiski method.'
    },
    {
      name: 'One-Time Pad',
      type: 'Polyalphabetic Substitution (OTP)',
      typeClass: 'sub',
      key: 'Random Key (Length = Message)',
      working: 'Combines plaintext with an equally long, truly random key stream modulo 26 used exactly once.',
      advantages: 'Mathematically proven by Claude Shannon (1949) to achieve Perfect Secrecy (Information-Theoretic Security).',
      limitations: 'Severe key distribution problem; key must equal message length and never be reused or sampled pseudo-randomly.',
      security: 'Information-Theoretically Secure IF key is truly random, secret, & single-use.'
    },
    {
      name: 'Rail Fence Cipher',
      type: 'Transposition (Zigzag)',
      typeClass: 'trans',
      key: 'Integer Number of Rails (r ≥ 1)',
      working: 'Writes plaintext along diagonal zigzag rails, then reads consecutive horizontal rows to construct ciphertext.',
      advantages: 'Preserves the entire character repertoire without requiring alphabetic normalization or padding.',
      limitations: 'Preserves 100% of unigram letter frequencies; small keyspace (rails < message length). Easily anagrammed.',
      security: 'Very Low. Trivial to break using simple trial of rail depths.'
    },
    {
      name: 'Columnar Transposition',
      type: 'Transposition (Permutation)',
      typeClass: 'trans',
      key: 'Alphabetic Keyword',
      working: 'Writes message row-by-row into a grid and outputs columns in alphabetical order of keyword characters.',
      advantages: 'Thoroughly scrambles adjacency of bigrams and trigrams; can be combined with substitution for product ciphers.',
      limitations: 'Unigram frequencies remain unchanged; vulnerable to multiple anagramming and crib-based cryptanalysis.',
      security: 'Low to Moderate. Broken via multiple anagramming techniques.'
    }
  ];


  /* --------------------------------------------------------------------------
     3.5 COSMIC STARFIELD & DIGITAL CONSTELLATION SIMULATOR
     -------------------------------------------------------------------------- */

  class CosmicStarfield {
    constructor(canvasId = 'spaceCanvas') {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.particles = [];
      this.animId = null;
      this.isRunning = true;
      this.isMotionReduced = false;
      this.maxDistance = 88;

      this.checkReducedMotion();
      this.resize();
      this.initParticles();
      this.initEvents();

      if (!this.isMotionReduced) {
        this.start();
      } else {
        this.renderOnce();
      }
    }

    checkReducedMotion() {
      const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
      this.isMotionReduced = mediaQuery.matches;
      if (mediaQuery.addEventListener) {
        mediaQuery.addEventListener('change', (e) => {
          this.isMotionReduced = e.matches;
          if (this.isMotionReduced) {
            this.pause();
            this.renderOnce();
          } else if (this.isRunning) {
            this.start();
          }
        });
      }
    }

    resize() {
      this.width = window.innerWidth;
      this.height = window.innerHeight;
      this.canvas.width = this.width;
      this.canvas.height = this.height;
    }

    initParticles() {
      this.particles = [];
      let count = 68;
      if (this.width < 768) {
        count = 24;
      } else if (this.width < 1024) {
        count = 40;
      }

      const colors = ['#F1F5F9', '#22D3EE', '#C084FC', '#818CF8'];

      for (let i = 0; i < count; i++) {
        this.particles.push({
          x: Math.random() * this.width,
          y: Math.random() * this.height,
          vx: (Math.random() - 0.5) * 0.25,
          vy: (Math.random() - 0.5) * 0.25,
          radius: Math.random() * 1.4 + 0.6,
          baseAlpha: Math.random() * 0.6 + 0.25,
          twinkleSpeed: Math.random() * 0.025 + 0.01,
          phase: Math.random() * Math.PI * 2,
          color: colors[Math.floor(Math.random() * colors.length)]
        });
      }
    }

    initEvents() {
      window.addEventListener('resize', () => {
        this.resize();
        this.initParticles();
        if (this.isMotionReduced || !this.isRunning) {
          this.renderOnce();
        }
      });

      document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
          this.pause();
        } else if (this.isRunning && !this.isMotionReduced) {
          this.start();
        }
      });
    }

    toggle() {
      this.isRunning = !this.isRunning;
      if (this.isRunning && !this.isMotionReduced) {
        this.start();
      } else {
        this.pause();
        this.renderOnce();
      }
      return this.isRunning;
    }

    start() {
      if (this.animId) cancelAnimationFrame(this.animId);
      const loop = () => {
        this.render();
        this.animId = requestAnimationFrame(loop);
      };
      this.animId = requestAnimationFrame(loop);
    }

    pause() {
      if (this.animId) {
        cancelAnimationFrame(this.animId);
        this.animId = null;
      }
    }

    render() {
      this.ctx.clearRect(0, 0, this.width, this.height);
      const pLen = this.particles.length;

      // Draw subtle digital constellation connections
      for (let i = 0; i < pLen; i++) {
        const p1 = this.particles[i];
        for (let j = i + 1; j < pLen; j++) {
          const p2 = this.particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < this.maxDistance) {
            const alpha = (1 - dist / this.maxDistance) * 0.15;
            this.ctx.beginPath();
            this.ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
            this.ctx.lineWidth = 0.75;
            this.ctx.moveTo(p1.x, p1.y);
            this.ctx.lineTo(p2.x, p2.y);
            this.ctx.stroke();
          }
        }
      }

      // Update and draw stars
      for (let i = 0; i < pLen; i++) {
        const p = this.particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = this.width;
        else if (p.x > this.width) p.x = 0;
        if (p.y < 0) p.y = this.height;
        else if (p.y > this.height) p.y = 0;

        p.phase += p.twinkleSpeed;
        const alpha = p.baseAlpha + Math.sin(p.phase) * 0.22;
        const clampedAlpha = Math.max(0.1, Math.min(1, alpha));

        this.ctx.beginPath();
        this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        this.ctx.fillStyle = p.color;
        this.ctx.globalAlpha = clampedAlpha;
        this.ctx.fill();
        this.ctx.globalAlpha = 1.0;
      }
    }

    renderOnce() {
      this.ctx.clearRect(0, 0, this.width, this.height);
      const pLen = this.particles.length;

      for (let i = 0; i < pLen; i++) {
        const p1 = this.particles[i];
        for (let j = i + 1; j < pLen; j++) {
          const p2 = this.particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < this.maxDistance) {
            const alpha = (1 - dist / this.maxDistance) * 0.12;
            this.ctx.beginPath();
            this.ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
            this.ctx.lineWidth = 0.75;
            this.ctx.moveTo(p1.x, p1.y);
            this.ctx.lineTo(p2.x, p2.y);
            this.ctx.stroke();
          }
        }
      }

      for (let i = 0; i < pLen; i++) {
        const p = this.particles[i];
        this.ctx.beginPath();
        this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        this.ctx.fillStyle = p.color;
        this.ctx.globalAlpha = p.baseAlpha;
        this.ctx.fill();
        this.ctx.globalAlpha = 1.0;
      }
    }
  }


  /* --------------------------------------------------------------------------
     4. APPLICATION CONTROLLER & UI MANAGEMENT
     -------------------------------------------------------------------------- */

  class CryptoApp {
    constructor() {
      this.currentCipherId = 'caesar';
      this.currentSectionId = 'dashboard-section';
      this.lastExecutionTime = 0;
      this.loadedFilePayload = null;
      this.loadedFileName = null;
      this.processedFileBlobUrl = null;

      this.initDOMElements();
      this.initEventListeners();
      this.populateDashboardAndCategories();
      this.populateComparisonTable();
      this.populateBenchmarkCheckboxes();
      this.updateKPICounters();
      this.updateWorkspaceCipher(this.currentCipherId);
      this.updateFileCipherEngine('caesar');
    }

    initDOMElements() {
      // Top Navigation & Controls
      this.cosmicToggleBtn = document.getElementById('cosmicToggleBtn');
      this.cosmicToggleLabel = document.getElementById('cosmicToggleLabel');
      this.navHelpQuickBtn = document.getElementById('navHelpQuickBtn');

      // Sidebar & Navigation
      this.sidebar = document.getElementById('sidebar');
      this.sidebarOpenBtn = document.getElementById('sidebarOpenBtn');
      this.sidebarCloseBtn = document.getElementById('sidebarCloseBtn');
      this.navItems = document.querySelectorAll('.nav-item');
      this.pageSections = document.querySelectorAll('.page-section');
      this.pageTitle = document.getElementById('pageTitle');
      this.pageSubtitle = document.getElementById('pageSubtitle');

      // Dashboard KPI Elements
      this.kpiTotal = document.getElementById('kpiTotal');
      this.kpiSub = document.getElementById('kpiSub');
      this.kpiTrans = document.getElementById('kpiTrans');
      this.kpiStatus = document.getElementById('kpiStatus');

      // Workspace Elements
      this.workspaceSelect = document.getElementById('workspaceCipherSelect');
      this.cipherTypeChip = document.getElementById('cipherTypeChip');
      this.cipherMathChip = document.getElementById('cipherMathChip');
      this.algoNameElem = document.getElementById('currentAlgoName');
      this.algoCategoryElem = document.getElementById('currentAlgoCategory');
      this.algoDescElem = document.getElementById('currentAlgoDesc');
      this.algoRulesElem = document.getElementById('currentAlgoRules');
      this.quickSampleBtn = document.getElementById('quickSampleBtn');

      this.keyActionsBar = document.getElementById('keyActionsBar');
      this.dynamicKeyControls = document.getElementById('dynamicKeyControls');
      this.keyValidationMsg = document.getElementById('keyValidationMsg');
      this.keyVisualizerDrawer = document.getElementById('keyVisualizerDrawer');

      this.cryptoInput = document.getElementById('cryptoInputText');
      this.cryptoOutput = document.getElementById('cryptoOutputText');
      this.outputCardPanel = document.getElementById('outputCardPanel');
      this.outputStatusBadge = document.getElementById('outputStatusBadge');
      this.inputCharCount = document.getElementById('inputCharCount');
      this.outputCharCount = document.getElementById('outputCharCount');
      this.execTimeDisplay = document.getElementById('execTimeDisplay');

      this.encryptBtn = document.getElementById('encryptBtn');
      this.decryptBtn = document.getElementById('decryptBtn');
      this.clearWorkspaceActionBtn = document.getElementById('clearWorkspaceActionBtn');
      this.swapIoBtn = document.getElementById('swapIoBtn');
      this.clearInputBtn = document.getElementById('clearInputBtn');
      this.pasteInputBtn = document.getElementById('pasteInputBtn');
      this.copyOutputBtn = document.getElementById('copyOutputBtn');
      this.saveOutputAsFileBtn = document.getElementById('saveOutputAsFileBtn');
      this.clearAllBtn = document.getElementById('clearAllBtn');

      this.traceBody = document.getElementById('traceBody');
      this.traceStatusChip = document.getElementById('traceStatusChip');

      // Benchmark Elements
      this.benchmarkPlaintext = document.getElementById('benchmarkPlaintext');
      this.benchmarkSelectAll = document.getElementById('benchmarkSelectAll');
      this.benchmarkCheckboxList = document.getElementById('benchmarkCheckboxList');
      this.runComparativeBtn = document.getElementById('runComparativeBtn');
      this.benchmarkResultsContainer = document.getElementById('benchmarkResultsContainer');

      // File Crypto Elements
      this.fileDropzone = document.getElementById('fileDropzone');
      this.fileInputElem = document.getElementById('fileInputElem');
      this.fileMetaPanel = document.getElementById('fileMetaPanel');
      this.fileMetaName = document.getElementById('fileMetaName');
      this.fileMetaSize = document.getElementById('fileMetaSize');
      this.fileMetaChars = document.getElementById('fileMetaChars');
      this.fileContentPreview = document.getElementById('fileContentPreview');
      this.fileCipherSelect = document.getElementById('fileCipherSelect');
      this.fileDynamicKeyControls = document.getElementById('fileDynamicKeyControls');
      this.fileKeyValidationMsg = document.getElementById('fileKeyValidationMsg');
      this.fileEncryptBtn = document.getElementById('fileEncryptBtn');
      this.fileDecryptBtn = document.getElementById('fileDecryptBtn');
      this.fileResultPreview = document.getElementById('fileResultPreview');
      this.fileResultStatus = document.getElementById('fileResultStatus');
      this.downloadResultFileBtn = document.getElementById('downloadResultFileBtn');
      this.loadResultIntoInputBtn = document.getElementById('loadResultIntoInputBtn');

      // Toast & Modal
      this.toastContainer = document.getElementById('toastContainer');
      this.confirmModalBackdrop = document.getElementById('confirmModalBackdrop');
      this.confirmModalTitle = document.getElementById('confirmModalTitle');
      this.confirmModalMessage = document.getElementById('confirmModalMessage');
      this.confirmModalCancelBtn = document.getElementById('confirmModalCancelBtn');
      this.confirmModalOkBtn = document.getElementById('confirmModalOkBtn');
      this.modalCloseBtn = document.getElementById('modalCloseBtn');
    }

    initEventListeners() {
      // Top Navigation Actions
      if (this.cosmicToggleBtn) {
        this.cosmicToggleBtn.addEventListener('click', () => {
          if (window.cosmicStarfield) {
            const active = window.cosmicStarfield.toggle();
            if (this.cosmicToggleLabel) {
              this.cosmicToggleLabel.textContent = active ? 'Stars: Active' : 'Stars: Paused';
            }
            this.showToast(active ? 'Cosmic starfield resumed' : 'Cosmic starfield paused', 'info');
          }
        });
      }

      if (this.navHelpQuickBtn) {
        this.navHelpQuickBtn.addEventListener('click', () => {
          this.navigateToSection('help-section');
        });
      }

      // Sidebar Navigation
      this.navItems.forEach(item => {
        item.addEventListener('click', () => {
          const targetSection = item.getAttribute('data-section');
          const fileMode = item.getAttribute('data-file-mode');
          this.navigateToSection(targetSection);

          if (targetSection === 'file-tools-section' && fileMode) {
            if (fileMode === 'encrypt' && this.fileEncryptBtn) {
              this.fileEncryptBtn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              this.fileEncryptBtn.focus();
            } else if (fileMode === 'decrypt' && this.fileDecryptBtn) {
              this.fileDecryptBtn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              this.fileDecryptBtn.focus();
            }
          }
        });
      });

      if (this.sidebarOpenBtn) {
        this.sidebarOpenBtn.addEventListener('click', () => {
          this.sidebar.classList.add('mobile-open');
        });
      }
      if (this.sidebarCloseBtn) {
        this.sidebarCloseBtn.addEventListener('click', () => {
          this.sidebar.classList.remove('mobile-open');
        });
      }

      // Workspace Cipher Select
      this.workspaceSelect.addEventListener('change', (e) => {
        this.updateWorkspaceCipher(e.target.value);
      });

      // Quick Sample Test Vector
      this.quickSampleBtn.addEventListener('click', () => {
        const cipher = CIPHER_REGISTRY[this.currentCipherId];
        if (cipher && cipher.sampleTestVector) {
          this.cryptoInput.value = cipher.sampleTestVector.plaintext;
          cipher.setKeyValue(cipher.sampleTestVector.key);
          this.validateCurrentKey();
          this.updateCharCounts();
          this.showToast(`Loaded syllabus test vector for ${cipher.name}`, 'info');
        }
      });

      // Character Count Updates
      this.cryptoInput.addEventListener('input', () => {
        this.updateCharCounts();
        this.validateCurrentKey();
        this.updateKPICounters();
      });

      // Encrypt & Decrypt Actions
      this.encryptBtn.addEventListener('click', () => this.handleEncryption());
      this.decryptBtn.addEventListener('click', () => this.handleDecryption());

      // Dedicated CLEAR Workspace Button in Action Row
      if (this.clearWorkspaceActionBtn) {
        this.clearWorkspaceActionBtn.addEventListener('click', () => this.confirmClearWorkspace());
      }

      // I/O Tools
      this.swapIoBtn.addEventListener('click', () => this.swapInputOutput());
      this.clearInputBtn.addEventListener('click', () => {
        this.cryptoInput.value = '';
        this.updateCharCounts();
        this.updateKPICounters();
      });
      this.pasteInputBtn.addEventListener('click', () => this.handlePaste());
      this.copyOutputBtn.addEventListener('click', () => this.copyToClipboard(this.cryptoOutput.value, 'Ciphertext output copied'));
      this.saveOutputAsFileBtn.addEventListener('click', () => this.exportOutputToFile());
      this.clearAllBtn.addEventListener('click', () => this.confirmClearWorkspace());

      // Benchmark Runner
      this.benchmarkSelectAll.addEventListener('change', (e) => {
        const checkboxes = this.benchmarkCheckboxList.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(cb => { cb.checked = e.target.checked; });
      });
      this.runComparativeBtn.addEventListener('click', () => this.runComparativeBenchmark());

      // File Operations
      this.fileDropzone.addEventListener('click', () => this.fileInputElem.click());
      this.fileInputElem.addEventListener('change', (e) => this.handleFileSelection(e.target.files[0]));
      this.fileDropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        this.fileDropzone.classList.add('dragover');
      });
      this.fileDropzone.addEventListener('dragleave', () => this.fileDropzone.classList.remove('dragover'));
      this.fileDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        this.fileDropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
          this.handleFileSelection(e.dataTransfer.files[0]);
        }
      });

      this.fileCipherSelect.addEventListener('change', (e) => {
        this.updateFileCipherEngine(e.target.value);
      });

      this.fileEncryptBtn.addEventListener('click', () => this.handleFileCrypto('encrypt'));
      this.fileDecryptBtn.addEventListener('click', () => this.handleFileCrypto('decrypt'));
      this.downloadResultFileBtn.addEventListener('click', () => this.downloadProcessedFile());
      this.loadResultIntoInputBtn.addEventListener('click', () => this.loadResultIntoSource());

      // FAQ Accordion
      const faqItems = document.querySelectorAll('.faq-item');
      faqItems.forEach(item => {
        const trigger = item.querySelector('.faq-trigger');
        trigger.addEventListener('click', () => {
          const isActive = item.classList.contains('active');
          faqItems.forEach(i => i.classList.remove('active'));
          if (!isActive) item.classList.add('active');
        });
      });
    }

    navigateToSection(sectionId) {
      this.currentSectionId = sectionId;
      this.pageSections.forEach(sec => {
        sec.classList.remove('active');
        if (sec.id === sectionId) sec.classList.add('active');
      });

      this.navItems.forEach(nav => {
        nav.classList.remove('active');
        if (nav.getAttribute('data-section') === sectionId) nav.classList.add('active');
      });

      // Update Header Titles based on active view
      const titles = {
        'dashboard-section': { title: 'Security Operations Console', sub: 'Classical Cryptographic Algorithms & Cryptanalysis Sandbox' },
        'workspace-section': { title: 'Cryptographic Workspace', sub: 'Interactive Symmetric Encryption, Modular Arithmetic & Inverse Matrix Inversion' },
        'substitution-section': { title: 'Substitution Ciphers Family', sub: 'Monoalphabetic and Polyalphabetic Alphabet Substitution Engines' },
        'transposition-section': { title: 'Transposition Ciphers Family', sub: 'Physical Character Permutation & Planar Geometric Ciphers' },
        'comparison-section': { title: 'Algorithm Comparison & Benchmarks', sub: 'Multi-Cipher Comparative Engine & Educational Security Analysis' },
        'file-tools-section': { title: 'Local File Cryptographic Utilities', sub: 'Client-Side Local Text File Encryption & Decryption Sandbox' },
        'help-section': { title: 'Classical Cryptography Reference Guide', sub: 'Syllabus Documentation, Mathematical Proofs & Security Advisories' }
      };

      const meta = titles[sectionId] || titles['dashboard-section'];
      this.pageTitle.textContent = meta.title;
      this.pageSubtitle.textContent = meta.sub;

      // Close mobile drawer if opened
      this.sidebar.classList.remove('mobile-open');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    navigateToWorkspace(cipherId) {
      this.navigateToSection('workspace-section');
      this.workspaceSelect.value = cipherId;
      this.updateWorkspaceCipher(cipherId);
    }

    updateKPICounters() {
      if (this.kpiTotal) {
        this.kpiTotal.textContent = Object.keys(CIPHER_REGISTRY).length;
      }
      if (this.kpiSub) {
        this.kpiSub.textContent = Object.values(CIPHER_REGISTRY).filter(c => c.family === 'substitution').length;
      }
      if (this.kpiTrans) {
        this.kpiTrans.textContent = Object.values(CIPHER_REGISTRY).filter(c => c.family === 'transposition').length;
      }
      if (this.kpiStatus) {
        const hasInput = this.cryptoInput && this.cryptoInput.value.trim().length > 0;
        const hasOutput = this.cryptoOutput && this.cryptoOutput.value.trim().length > 0;
        this.kpiStatus.textContent = (hasInput || hasOutput) ? 'Active' : 'Ready';
      }
    }


    /* ------------------------------------------------------------------------
       DASHBOARD & CIPHER CARD GENERATION
       ------------------------------------------------------------------------ */
    populateDashboardAndCategories() {
      const dashboardGrid = document.getElementById('dashboardCipherGrid');
      const subGrid = document.getElementById('substitutionCardsGrid');
      const transGrid = document.getElementById('transpositionCardsGrid');

      if (!dashboardGrid || !subGrid || !transGrid) return;

      dashboardGrid.innerHTML = '';
      subGrid.innerHTML = '';
      transGrid.innerHTML = '';

      // Dedicated geometric SVG icons for each classical algorithm
      const CIPHER_ICONS = {
        caesar: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><path d="m14 8 2.5-2.5M7.5 16.5 10 14"/></svg>`,
        monoalphabetic: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m3 7 3-4 3 4M6 3v12"/><path d="m21 17-3 4-3-4M18 7v14"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/></svg>`,
        playfair: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="7.5" y1="3" x2="7.5" y2="21"/><line x1="12" y1="3" x2="12" y2="21"/><line x1="16.5" y1="3" x2="16.5" y2="21"/><line x1="3" y1="7.5" x2="21" y2="7.5"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="16.5" x2="21" y2="16.5"/></svg>`,
        hill: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h3v16H4M20 4h-3v16h3"/><circle cx="9" cy="9" r="1.5"/><circle cx="15" cy="9" r="1.5"/><circle cx="9" cy="15" r="1.5"/><circle cx="15" cy="15" r="1.5"/></svg>`,
        vigenere: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M3 12h18M3 18h18"/><path d="m5 6 7 12 7-12"/></svg>`,
        otp: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16.5" r="1.5"/><path d="M12 18v2.5"/></svg>`,
        railfence: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6l4.5 12 4.5-12 4.5 12L21 6"/><circle cx="3" cy="6" r="1.5"/><circle cx="7.5" cy="18" r="1.5"/><circle cx="12" cy="6" r="1.5"/><circle cx="16.5" cy="18" r="1.5"/><circle cx="21" cy="6" r="1.5"/></svg>`,
        columnar: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/><path d="m6 8 0 4M6 12l-1.5-1.5M6 12l1.5-1.5"/><path d="m12 14 0-4M12 10l-1.5 1.5M12 10l1.5 1.5"/><path d="m18 8 0 4M18 12l-1.5-1.5M18 12l1.5-1.5"/></svg>`
      };

      Object.values(CIPHER_REGISTRY).forEach(cipher => {
        const iconSvg = CIPHER_ICONS[cipher.id] || `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
        const cardHtml = `
          <div class="cipher-card" data-cipher="${cipher.id}">
            <div>
              <div class="cipher-card-header">
                <div class="cipher-card-title-group">
                  <div class="cipher-icon-box" title="${cipher.name} Core Icon">
                    ${iconSvg}
                  </div>
                  <span class="cipher-card-title">${cipher.name}</span>
                </div>
                <span class="cipher-card-tag ${cipher.family === 'substitution' ? 'sub' : 'trans'}">${cipher.family}</span>
              </div>
              <p class="cipher-card-desc">${cipher.description}</p>
              <div class="cipher-card-formula">${cipher.mathFormula}</div>
            </div>
            <div class="cipher-card-footer">
              <span class="cipher-card-key-badge">${cipher.categoryLabel}</span>
              <span class="cipher-card-open">
                Launch Workspace
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
              </span>
            </div>
          </div>
        `;

        // Add to general dashboard
        const cardEl1 = this.createCardElement(cardHtml, cipher.id);
        dashboardGrid.appendChild(cardEl1);

        // Add to family category grids
        if (cipher.family === 'substitution') {
          const cardElSub = this.createCardElement(cardHtml, cipher.id);
          subGrid.appendChild(cardElSub);
        } else {
          const cardElTrans = this.createCardElement(cardHtml, cipher.id);
          transGrid.appendChild(cardElTrans);
        }
      });
    }

    createCardElement(html, cipherId) {
      const div = document.createElement('div');
      div.innerHTML = html.trim();
      const el = div.firstElementChild;
      el.addEventListener('click', () => {
        this.navigateToWorkspace(cipherId);
      });
      return el;
    }


    /* ------------------------------------------------------------------------
       WORKSPACE DYNAMIC CONFIGURATION
       ------------------------------------------------------------------------ */
    updateWorkspaceCipher(cipherId) {
      const cipher = CIPHER_REGISTRY[cipherId];
      if (!cipher) return;

      this.currentCipherId = cipherId;
      this.algoNameElem.textContent = cipher.name;
      this.algoCategoryElem.textContent = cipher.categoryLabel;
      this.algoDescElem.textContent = cipher.description;
      this.cipherTypeChip.textContent = `Type: ${cipher.family.toUpperCase()}`;
      this.cipherMathChip.textContent = cipher.mathFormula;

      // Populate rules bar
      this.algoRulesElem.innerHTML = '';
      cipher.rules.forEach(rule => {
        const item = document.createElement('span');
        item.className = 'algo-rule-item';
        item.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> ${rule}`;
        this.algoRulesElem.appendChild(item);
      });

      // Render Dynamic Key Controls
      this.keyActionsBar.innerHTML = '';
      this.dynamicKeyControls.innerHTML = '';
      this.keyVisualizerDrawer.innerHTML = '';
      this.keyVisualizerDrawer.classList.remove('active');

      if (cipher.renderHeaderActions) {
        cipher.renderHeaderActions(this.keyActionsBar, () => {
          this.validateCurrentKey();
          this.renderVisualizerIfApplicable();
        });
      }

      cipher.renderKeyControls(this.dynamicKeyControls, () => {
        this.validateCurrentKey();
        this.renderVisualizerIfApplicable();
      });

      this.validateCurrentKey();
      this.renderVisualizerIfApplicable();
      this.updateCharCounts();
    }

    validateCurrentKey() {
      const cipher = CIPHER_REGISTRY[this.currentCipherId];
      if (!cipher) return false;

      const keyVal = cipher.getKeyValue();
      const contextText = this.cryptoInput.value;
      const res = cipher.validateKey(keyVal, contextText);

      this.keyValidationMsg.className = 'validation-message';
      if (res.valid) {
        this.keyValidationMsg.classList.add('success');
        this.keyValidationMsg.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><polyline points="20 6 9 17 4 12"/></svg> ${res.message || 'Key valid'}`;
        return true;
      } else {
        this.keyValidationMsg.classList.add('error');
        this.keyValidationMsg.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> ${res.error}`;
        return false;
      }
    }

    renderVisualizerIfApplicable() {
      const cipher = CIPHER_REGISTRY[this.currentCipherId];
      if (cipher && cipher.renderVisualizer) {
        cipher.renderVisualizer(this.keyVisualizerDrawer, cipher.getKeyValue());
      } else {
        this.keyVisualizerDrawer.classList.remove('active');
        this.keyVisualizerDrawer.innerHTML = '';
      }
    }

    updateCharCounts() {
      const text = this.cryptoInput.value;
      const letters = (text.match(/[a-zA-Z]/g) || []).length;
      this.inputCharCount.textContent = `${text.length} characters • ${letters} letters`;

      const outText = this.cryptoOutput.value;
      this.outputCharCount.textContent = `${outText.length} characters`;
    }


    /* ------------------------------------------------------------------------
       CORE ENCRYPTION & DECRYPTION ACTIONS
       ------------------------------------------------------------------------ */
    handleEncryption() {
      const plaintext = this.cryptoInput.value;
      if (!plaintext) {
        this.showToast('Please enter an input message to encrypt.', 'error');
        this.cryptoInput.focus();
        return;
      }

      if (!this.validateCurrentKey()) {
        this.showToast('Please fix invalid key configuration before encrypting.', 'error');
        return;
      }

      const cipher = CIPHER_REGISTRY[this.currentCipherId];
      const keyVal = cipher.getKeyValue();

      try {
        const t0 = performance.now();
        const { output, trace } = cipher.encrypt(plaintext, keyVal);
        const t1 = performance.now();
        const duration = (t1 - t0).toFixed(2);

        this.cryptoOutput.value = output;
        this.updateCharCounts();
        this.execTimeDisplay.textContent = `Encryption: ${duration} ms`;
        this.renderTrace('Encryption Completed', trace, duration);

        // Visual feedback & output status badge
        if (this.outputCardPanel) {
          this.outputCardPanel.classList.remove('output-success-glow');
          void this.outputCardPanel.offsetWidth;
          this.outputCardPanel.classList.add('output-success-glow');
          setTimeout(() => this.outputCardPanel.classList.remove('output-success-glow'), 1800);
        }
        if (this.outputStatusBadge) {
          this.outputStatusBadge.textContent = 'ENCRYPTION COMPLETED';
          this.outputStatusBadge.className = 'output-status-chip success';
        }
        this.updateKPICounters();
        this.showToast(`${cipher.name} encryption successful! (${duration} ms)`, 'success');
      } catch (err) {
        console.error(err);
        this.showToast(`Encryption failed: ${err.message}`, 'error');
      }
    }

    handleDecryption() {
      const ciphertext = this.cryptoInput.value;
      if (!ciphertext) {
        this.showToast('Please enter ciphertext in the input box to decrypt.', 'error');
        this.cryptoInput.focus();
        return;
      }

      if (!this.validateCurrentKey()) {
        this.showToast('Please fix invalid key configuration before decrypting.', 'error');
        return;
      }

      const cipher = CIPHER_REGISTRY[this.currentCipherId];
      const keyVal = cipher.getKeyValue();

      try {
        const t0 = performance.now();
        const { output, trace } = cipher.decrypt(ciphertext, keyVal);
        const t1 = performance.now();
        const duration = (t1 - t0).toFixed(2);

        this.cryptoOutput.value = output;
        this.updateCharCounts();
        this.execTimeDisplay.textContent = `Decryption: ${duration} ms`;
        this.renderTrace('Decryption Completed', trace, duration);

        // Visual feedback & output status badge
        if (this.outputCardPanel) {
          this.outputCardPanel.classList.remove('output-success-glow');
          void this.outputCardPanel.offsetWidth;
          this.outputCardPanel.classList.add('output-success-glow');
          setTimeout(() => this.outputCardPanel.classList.remove('output-success-glow'), 1800);
        }
        if (this.outputStatusBadge) {
          this.outputStatusBadge.textContent = 'DECRYPTION COMPLETED';
          this.outputStatusBadge.className = 'output-status-chip success';
        }
        this.updateKPICounters();
        this.showToast(`${cipher.name} decryption successful! (${duration} ms)`, 'success');
      } catch (err) {
        console.error(err);
        this.showToast(`Decryption failed: ${err.message}`, 'error');
      }
    }

    renderTrace(title, traceItems, duration) {
      this.traceStatusChip.textContent = `${title} (${duration} ms)`;
      if (!traceItems || traceItems.length === 0) {
        this.traceBody.innerHTML = `<p class="trace-empty-hint">No trace steps generated for this operation.</p>`;
        return;
      }

      let html = '';
      traceItems.forEach((item, idx) => {
        html += `
          <div class="trace-item">
            <span class="trace-step">#${idx + 1}</span>
            <span class="trace-calc">${item}</span>
          </div>
        `;
      });
      this.traceBody.innerHTML = html;
    }

    swapInputOutput() {
      const out = this.cryptoOutput.value;
      if (!out) {
        this.showToast('Output is empty; cannot swap.', 'info');
        return;
      }
      this.cryptoInput.value = out;
      this.cryptoOutput.value = '';
      this.updateCharCounts();
      this.showToast('Output swapped into Input message area.', 'info');
    }

    async handlePaste() {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const text = await navigator.clipboard.readText();
          this.cryptoInput.value = text;
          this.updateCharCounts();
          this.validateCurrentKey();
          this.showToast('Text pasted from clipboard.', 'info');
        } else {
          this.showToast('Clipboard read access is not permitted in this browser context.', 'error');
        }
      } catch (err) {
        this.showToast('Unable to read clipboard: ' + err.message, 'error');
      }
    }

    async copyToClipboard(text, successMsg) {
      if (!text) {
        this.showToast('No text available to copy.', 'error');
        return;
      }
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          // Fallback using temporary textarea
          const ta = document.createElement('textarea');
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
        }
        this.showToast(successMsg || 'Copied to clipboard!', 'success');
      } catch (err) {
        this.showToast('Failed to copy to clipboard.', 'error');
      }
    }

    exportOutputToFile() {
      const text = this.cryptoOutput.value;
      if (!text) {
        this.showToast('No output content available to export.', 'error');
        return;
      }
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${this.currentCipherId}_output.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      this.showToast(`Saved ${this.currentCipherId}_output.txt`, 'success');
    }

    confirmClearWorkspace() {
      if (!this.cryptoInput.value && !this.cryptoOutput.value) {
        this.showToast('Workspace is already empty.', 'info');
        return;
      }
      this.showConfirmModal(
        'Clear Workspace Data',
        'Are you sure you want to clear both the input and output message buffers? Any unsaved changes will be lost.',
        () => {
          this.cryptoInput.value = '';
          this.cryptoOutput.value = '';
          this.updateCharCounts();
          this.traceBody.innerHTML = `<p class="trace-empty-hint">Perform an encryption or decryption operation above to inspect mathematical steps.</p>`;
          this.traceStatusChip.textContent = 'Awaiting Execution';
          this.execTimeDisplay.textContent = 'Execution: Ready (0.00 ms)';
          if (this.outputStatusBadge) {
            this.outputStatusBadge.textContent = 'IDLE';
            this.outputStatusBadge.className = 'output-status-chip';
          }
          this.updateKPICounters();
          this.showToast('Workspace fields cleared.', 'info');
        }
      );
    }


    /* ------------------------------------------------------------------------
       5. ALGORITHM COMPARISON MODULE
       ------------------------------------------------------------------------ */
    populateComparisonTable() {
      const tbody = document.getElementById('comparisonTableBody');
      if (!tbody) return;

      tbody.innerHTML = '';
      COMPARISON_DATA.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="algo-cell">${row.name}</td>
          <td><span class="type-tag ${row.typeClass === 'sub' ? 'chip-violet' : 'chip-cyan'}">${row.type}</span></td>
          <td><code>${row.key}</code></td>
          <td>${row.working}</td>
          <td>${row.advantages}</td>
          <td>${row.limitations}</td>
          <td><strong style="color:var(--text-main);">${row.security}</strong></td>
        `;
        tbody.appendChild(tr);
      });
    }

    populateBenchmarkCheckboxes() {
      const container = this.benchmarkCheckboxList;
      if (!container) return;

      container.innerHTML = '';
      Object.values(CIPHER_REGISTRY).forEach(cipher => {
        const label = document.createElement('label');
        label.className = 'checkbox-container';
        label.innerHTML = `
          <input type="checkbox" value="${cipher.id}" checked>
          <span>${cipher.name}</span>
        `;
        container.appendChild(label);
      });
    }

    runComparativeBenchmark() {
      const text = this.benchmarkPlaintext.value;
      if (!text || text.trim() === '') {
        this.showToast('Please enter a shared plaintext test vector.', 'error');
        return;
      }

      const checkedBoxes = Array.from(this.benchmarkCheckboxList.querySelectorAll('input[type="checkbox"]:checked'));
      if (checkedBoxes.length === 0) {
        this.showToast('Please select at least one algorithm to run.', 'error');
        return;
      }

      const results = [];

      checkedBoxes.forEach(cb => {
        const cipherId = cb.value;
        const cipher = CIPHER_REGISTRY[cipherId];
        let testKey = cipher.defaultKey;

        // Special handling for OTP key length in benchmark
        if (cipherId === 'otp') {
          const alphaLen = (text.match(/[a-zA-Z]/g) || []).length;
          testKey = generateRandomKeyString(Math.max(alphaLen, 5));
        }

        try {
          const t0 = performance.now();
          const { output } = cipher.encrypt(text, testKey);
          const t1 = performance.now();
          const duration = (t1 - t0).toFixed(3);

          results.push({
            id: cipherId,
            name: cipher.name,
            keyUsed: testKey,
            cipherText: output,
            timeMs: duration,
            status: 'Success'
          });
        } catch (err) {
          results.push({
            id: cipherId,
            name: cipher.name,
            keyUsed: testKey,
            cipherText: 'Error: ' + err.message,
            timeMs: '0.000',
            status: 'Failed'
          });
        }
      });

      this.renderBenchmarkResults(results);
      this.showToast(`Executed comparative run across ${results.length} ciphers!`, 'success');
    }

    renderBenchmarkResults(results) {
      const container = this.benchmarkResultsContainer;
      let cardsHtml = '<div class="benchmark-results-grid">';

      results.forEach(res => {
        cardsHtml += `
          <div class="benchmark-result-card">
            <div class="benchmark-res-header">
              <span class="benchmark-res-name">${res.name}</span>
              <span class="benchmark-res-time">${res.timeMs} ms</span>
            </div>
            <div class="benchmark-res-key">Key: ${res.keyUsed}</div>
            <div class="benchmark-res-output">${res.cipherText}</div>
          </div>
        `;
      });
      cardsHtml += '</div>';
      container.innerHTML = cardsHtml;
    }


    /* ------------------------------------------------------------------------
       6. LOCAL FILE ENCRYPTION / DECRYPTION MODULE
       ------------------------------------------------------------------------ */
    handleFileSelection(file) {
      if (!file) return;
      if (!file.name.endsWith('.txt') && file.type && !file.type.includes('text')) {
        this.showToast('Please select a valid plain text (.txt) file.', 'error');
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target.result;
        this.loadedFilePayload = content;
        this.loadedFileName = file.name;

        this.fileMetaPanel.style.display = 'flex';
        this.fileMetaName.textContent = file.name;
        this.fileMetaSize.textContent = `${(file.size / 1024).toFixed(2)} KB`;
        this.fileMetaChars.textContent = `${content.length} chars`;

        this.fileContentPreview.value = content;
        this.validateFileKey();
        this.showToast(`Loaded ${file.name} successfully into memory.`, 'success');
      };
      reader.onerror = () => {
        this.showToast('Failed to read local file.', 'error');
      };
      reader.readAsText(file);
    }

    updateFileCipherEngine(cipherId) {
      const cipher = CIPHER_REGISTRY[cipherId];
      if (!cipher) return;

      this.fileDynamicKeyControls.innerHTML = '';
      cipher.renderKeyControls(this.fileDynamicKeyControls, () => this.validateFileKey());
      this.validateFileKey();
    }

    validateFileKey() {
      const cipherId = this.fileCipherSelect.value;
      const cipher = CIPHER_REGISTRY[cipherId];
      if (!cipher) return false;

      // Extract key input within file section
      const inputs = this.fileDynamicKeyControls.querySelectorAll('input');
      let keyVal = cipher.defaultKey;

      if (cipherId === 'hill') {
        const vals = Array.from(inputs).map(inp => inp.value.trim());
        keyVal = vals.join(',');
      } else if (inputs.length > 0) {
        keyVal = inputs[0].value.trim();
      }

      const res = cipher.validateKey(keyVal, this.loadedFilePayload);
      this.fileKeyValidationMsg.className = 'validation-message';

      if (res.valid) {
        this.fileKeyValidationMsg.classList.add('success');
        this.fileKeyValidationMsg.textContent = res.message || 'Key valid for file processing.';
        return { valid: true, keyVal };
      } else {
        this.fileKeyValidationMsg.classList.add('error');
        this.fileKeyValidationMsg.textContent = res.error;
        return { valid: false, keyVal };
      }
    }

    handleFileCrypto(operation) {
      if (!this.loadedFilePayload) {
        this.showToast('Please select and load a local .txt file first.', 'error');
        return;
      }

      const keyCheck = this.validateFileKey();
      if (!keyCheck.valid) {
        this.showToast('Cannot proceed: invalid key specification.', 'error');
        return;
      }

      const cipherId = this.fileCipherSelect.value;
      const cipher = CIPHER_REGISTRY[cipherId];

      try {
        const t0 = performance.now();
        const res = operation === 'encrypt'
          ? cipher.encrypt(this.loadedFilePayload, keyCheck.keyVal)
          : cipher.decrypt(this.loadedFilePayload, keyCheck.keyVal);
        const t1 = performance.now();
        const duration = (t1 - t0).toFixed(2);

        this.fileResultPreview.value = res.output;
        this.fileResultStatus.textContent = `${operation.toUpperCase()}ED (${duration} ms)`;
        this.downloadResultFileBtn.disabled = false;
        this.loadResultIntoInputBtn.disabled = false;

        // Generate download Blob
        if (this.processedFileBlobUrl) {
          URL.revokeObjectURL(this.processedFileBlobUrl);
        }
        const blob = new Blob([res.output], { type: 'text/plain;charset=utf-8' });
        this.processedFileBlobUrl = URL.createObjectURL(blob);

        this.showToast(`File payload ${operation}ed successfully! (${duration} ms)`, 'success');
      } catch (err) {
        console.error(err);
        this.showToast(`File ${operation} error: ${err.message}`, 'error');
      }
    }

    downloadProcessedFile() {
      if (!this.processedFileBlobUrl) return;
      const cipherId = this.fileCipherSelect.value;
      const baseName = (this.loadedFileName || 'file').replace(/\.txt$/i, '');
      const downloadName = `${baseName}_${cipherId}_processed.txt`;

      const a = document.createElement('a');
      a.href = this.processedFileBlobUrl;
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      this.showToast(`Downloaded ${downloadName}`, 'success');
    }

    loadResultIntoSource() {
      const resultText = this.fileResultPreview.value;
      if (!resultText) return;
      this.loadedFilePayload = resultText;
      this.fileContentPreview.value = resultText;
      this.fileMetaChars.textContent = `${resultText.length} chars`;
      this.fileResultPreview.value = '';
      this.downloadResultFileBtn.disabled = true;
      this.loadResultIntoInputBtn.disabled = true;
      this.showToast('Processed result loaded back into Source Payload for reverse verification.', 'info');
    }


    /* ------------------------------------------------------------------------
       7. TOAST NOTIFICATIONS & MODALS
       ------------------------------------------------------------------------ */
    showToast(message, type = 'info') {
      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;

      let iconSvg = '';
      if (type === 'success') {
        iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
      } else if (type === 'error') {
        iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
      } else {
        iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
      }

      toast.innerHTML = `${iconSvg}<span>${message}</span>`;
      this.toastContainer.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => {
          if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 220);
      }, 3400);
    }

    showConfirmModal(title, message, onConfirm) {
      this.confirmModalTitle.textContent = title;
      this.confirmModalMessage.textContent = message;
      this.confirmModalBackdrop.style.display = 'flex';

      const cleanup = () => {
        this.confirmModalBackdrop.style.display = 'none';
        this.confirmModalOkBtn.onclick = null;
        this.confirmModalCancelBtn.onclick = null;
        this.modalCloseBtn.onclick = null;
      };

      this.confirmModalOkBtn.onclick = () => {
        cleanup();
        onConfirm();
      };
      this.confirmModalCancelBtn.onclick = cleanup;
      this.modalCloseBtn.onclick = cleanup;
    }
  }

  // Initialize Application & Cosmic Canvas once DOM Content is loaded
  document.addEventListener('DOMContentLoaded', () => {
    window.cosmicStarfield = new CosmicStarfield('spaceCanvas');
    window.cryptoApp = new CryptoApp();
  });

})();
