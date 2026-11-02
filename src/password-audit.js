(function (root, factory) {
  const api = factory();

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.PasswordAudit = api;
  }
})(typeof globalThis === "object" ? globalThis : this, function () {
  const COMMON_PASSWORDS = [
    "123456",
    "123456789",
    "12345678",
    "12345",
    "1234567",
    "1234567890",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "master",
    "trustno1",
    "login",
    "abc123",
    "passw0rd",
    "correcthorsebatterystaple",
    "troubador",
    "troubadour"
  ];

  const COMMON_WORDS = [
    "password",
    "welcome",
    "admin",
    "qwerty",
    "letmein",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "secret",
    "summer",
    "winter",
    "spring",
    "autumn",
    "flower",
    "family",
    "love",
    "angel",
    "freedom",
    "whatever",
    "trustno",
    "troubador",
    "troubadour"
  ];

  const COMMON_PASSWORD_SET = new Set(COMMON_PASSWORDS);
  const SCORE_LABELS = ["Weak", "Weak", "Fair", "Good", "Strong"];
  const GENERATOR_CHARACTERS = Object.freeze({
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{}:,.?"
  });
  function createRandomIndex(secureRandom) {
    return function (maximum) {
      const range = 0x100000000;
      const limit = Math.floor(range / maximum) * maximum;
      const value = new Uint32Array(1);
      do {
        secureRandom.getRandomValues(value);
      } while (value[0] >= limit);
      return value[0] % maximum;
    };
  }

  function getSecureRandom(cryptoProvider) {
    const secureRandom = cryptoProvider ||
      (typeof globalThis === "object" ? globalThis.crypto : null);
    if (!secureRandom || typeof secureRandom.getRandomValues !== "function") {
      throw new Error("Secure random generation is unavailable in this browser.");
    }
    return secureRandom;
  }

  function generatePassword(length, options, cryptoProvider) {
    if (!Number.isInteger(length) || length < 8 || length > 30) {
      throw new RangeError("Choose a password length between 8 and 30 characters.");
    }

    const settings = options || {};
    const selectedSets = Object.keys(GENERATOR_CHARACTERS)
      .filter(function (name) {
        return settings[name] !== false;
      })
      .map(function (name) {
        const characterSet = GENERATOR_CHARACTERS[name];
        return settings.avoidLookalikes
          ? characterSet.replace(/[Il1O0]/g, "")
          : characterSet;
      })
      .filter(function (characterSet) {
        return characterSet.length > 0;
      });

    if (selectedSets.length === 0) {
      throw new RangeError("At least one character type must be enabled.");
    }

    const randomIndex = createRandomIndex(getSecureRandom(cryptoProvider));

    const allCharacters = selectedSets.join("");
    const characters = selectedSets.map(function (characterSet) {
      return characterSet[randomIndex(characterSet.length)];
    });

    while (characters.length < length) {
      characters.push(allCharacters[randomIndex(allCharacters.length)]);
    }

    for (let index = characters.length - 1; index > 0; index -= 1) {
      const otherIndex = randomIndex(index + 1);
      [characters[index], characters[otherIndex]] = [characters[otherIndex], characters[index]];
    }

    return characters.join("");
  }

  function normalizeLeet(password) {
    return password.toLowerCase().replace(/[013457@$!]/g, function (character) {
      const substitutions = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i"
      };
      return substitutions[character];
    });
  }

  function getCharacterPool(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    if (Array.from(password).some(function (character) {
      return character.codePointAt(0) > 127;
    })) {
      pool += 100;
    }
    return pool;
  }

  function containsSequence(password) {
    const value = password.toLowerCase();
    const sequences = [
      "abcdefghijklmnopqrstuvwxyz",
      "0123456789",
      "qwertyuiop",
      "asdfghjkl",
      "zxcvbnm"
    ];

    for (const sequence of sequences) {
      const reversed = Array.from(sequence).reverse().join("");
      for (let index = 0; index <= sequence.length - 4; index += 1) {
        const part = sequence.slice(index, index + 4);
        if (value.includes(part) || value.includes(Array.from(part).reverse().join(""))) {
          return true;
        }

        const reversePart = reversed.slice(index, index + 4);
        if (value.includes(reversePart)) {
          return true;
        }
      }
    }

    for (let index = 0; index <= value.length - 4; index += 1) {
      const first = value.charCodeAt(index);
      const second = value.charCodeAt(index + 1);
      const third = value.charCodeAt(index + 2);
      const fourth = value.charCodeAt(index + 3);
      if (second - first === 1 && third - second === 1 && fourth - third === 1) {
        return true;
      }
      if (second - first === -1 && third - second === -1 && fourth - third === -1) {
        return true;
      }
    }
    return false;
  }

  function containsRepeatedPattern(password) {
    const characters = Array.from(password);
    if (/(.)\1{2,}/u.test(password)) {
      return true;
    }

    for (let chunkLength = 1; chunkLength <= Math.min(4, Math.floor(characters.length / 2)); chunkLength += 1) {
      for (let start = 0; start + chunkLength * 2 <= characters.length; start += 1) {
        const firstChunk = characters.slice(start, start + chunkLength).join("");
        const secondChunk = characters.slice(start + chunkLength, start + chunkLength * 2).join("");
        if (firstChunk === secondChunk) {
          return true;
        }
      }
    }
    return false;
  }

  function findDictionaryWord(normalizedPassword) {
    return COMMON_WORDS.find(function (word) {
      return normalizedPassword.includes(word);
    }) || null;
  }

  function getSuggestions(password, checks, findings) {
    const suggestions = [];

    if (password.length < 14) {
      suggestions.push("For extra protection, aim for 14 or more characters; longer passwords are harder to guess.");
    }
    if (!checks.uppercase || !checks.lowercase || !checks.number || !checks.symbol) {
      suggestions.push("Mix uppercase and lowercase letters, numbers, and symbols where it feels natural.");
    }
    if (findings.commonPassword || findings.dictionaryWord) {
      suggestions.push("Avoid common passwords, names, and dictionary words—even when you swap letters for symbols.");
    }
    if (findings.sequence) {
      suggestions.push("Replace keyboard walks and alphabet or number sequences with unrelated characters.");
    }
    if (findings.repeatedPattern) {
      suggestions.push("Avoid repeating the same character or short pattern.");
    }
    if (suggestions.length === 0) {
      suggestions.push("Keep it unique to one account and store it in a trusted password manager.");
    }
    return suggestions;
  }

  function analyzePassword(password) {
    if (typeof password !== "string") {
      throw new TypeError("Password must be a string.");
    }

    const characters = Array.from(password);
    const length = characters.length;
    const checks = {
      length: length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      symbol: /[^A-Za-z0-9]/.test(password)
    };

    if (length === 0) {
      return {
        score: 0,
        label: "Waiting",
        entropyBits: 0,
        checks,
        findings: {
          commonPassword: false,
          dictionaryWord: false,
          sequence: false,
          repeatedPattern: false
        },
        suggestions: [
          "Use a long, unique password that you do not reuse.",
          "Consider a password manager for creating and storing passwords."
        ]
      };
    }

    const normalized = normalizeLeet(password).replace(/[^a-z0-9]/g, "");
    const commonPassword = COMMON_PASSWORD_SET.has(normalized) ||
      COMMON_PASSWORDS.some(function (commonPasswordValue) {
        return normalized.includes(commonPasswordValue);
      });
    const dictionaryWord = findDictionaryWord(normalized) !== null;
    const sequence = containsSequence(password);
    const repeatedPattern = containsRepeatedPattern(password);
    const pool = getCharacterPool(password);
    const rawEntropy = length * Math.log2(Math.max(pool, 1));
    const penalty =
      (commonPassword ? 25 : dictionaryWord ? 12 : 0) +
      (sequence ? 12 : 0) +
      (repeatedPattern ? 12 : 0);
    const entropyBits = Math.max(0, Math.round(rawEntropy - penalty));

    let score = 0;
    if (entropyBits >= 60) score = 4;
    else if (entropyBits >= 40) score = 3;
    else if (entropyBits >= 28) score = 2;
    else if (entropyBits >= 16) score = 1;

    if (commonPassword) score = Math.min(score, 1);
    if (sequence || repeatedPattern) score = Math.min(score, 2);
    if (dictionaryWord) score = Math.min(score, 3);
    if (length >= 21 && length <= 30) score = 4;

    const findings = {
      commonPassword,
      dictionaryWord,
      sequence,
      repeatedPattern
    };

    return {
      score,
      label: score === 4 && length >= 21 && length <= 30 ? "Very strong" : SCORE_LABELS[score],
      entropyBits,
      checks,
      findings,
      suggestions: getSuggestions(password, checks, findings)
    };
  }

  return Object.freeze({ analyzePassword, generatePassword });
});
