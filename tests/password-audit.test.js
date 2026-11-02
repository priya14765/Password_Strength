const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzePassword, generatePassword } = require("../src/password-audit.js");

test("empty password returns a waiting result", function () {
  const result = analyzePassword("");

  assert.equal(result.label, "Waiting");
  assert.equal(result.score, 0);
  assert.equal(result.entropyBits, 0);
  assert.equal(result.suggestions.length > 0, true);
});

test("common passwords and common symbol substitutions are flagged", function () {
  const result = analyzePassword("P@ssw0rd!");

  assert.equal(result.findings.commonPassword, true);
  assert.equal(result.label, "Weak");
  assert.ok(result.suggestions.some(function (suggestion) {
    return suggestion.includes("common passwords");
  }));
});

test("alphabetic and numeric sequences are identified", function () {
  const result = analyzePassword("abcdef1234");

  assert.equal(result.findings.sequence, true);
  assert.ok(result.score <= 2);
});

test("repeated characters and repeated chunks are identified", function () {
  assert.equal(analyzePassword("aaaaaaaaaaaa").findings.repeatedPattern, true);
  assert.equal(analyzePassword("abcabcabcabc").findings.repeatedPattern, true);
  assert.equal(analyzePassword("QabcabcZ9!").findings.repeatedPattern, true);
});

test("a long varied password without common patterns scores strong", function () {
  const result = analyzePassword("G7!vQ2#rLm9@xB4p");

  assert.equal(result.label, "Strong");
  assert.equal(result.score, 4);
  assert.equal(result.findings.commonPassword, false);
  assert.equal(result.findings.sequence, false);
  assert.equal(result.findings.repeatedPattern, false);
});

test("every password from 21 through 30 characters is labeled very strong", function () {
  for (const length of [21, 25, 30]) {
    const result = analyzePassword("a".repeat(length));

    assert.equal(result.score, 4);
    assert.equal(result.label, "Very strong");
  }
  assert.notEqual(analyzePassword("a".repeat(20)).label, "Very strong");
  assert.notEqual(analyzePassword("a".repeat(31)).label, "Very strong");
});

test("the 8-character minimum is enforced at the exact boundary", function () {
  assert.equal(analyzePassword("Ab1!xyz").checks.length, false);
  assert.equal(analyzePassword("Ab1!xyza").checks.length, true);
});

test("checklist reflects length and character classes", function () {
  const result = analyzePassword("LongerExample9!");

  assert.deepEqual(result.checks, {
    length: true,
    lowercase: true,
    uppercase: true,
    number: true,
    symbol: true
  });
});

test("analysis result does not include the supplied password", function () {
  const result = analyzePassword("Example123!");

  assert.equal(Object.hasOwn(result, "password"), false);
});

test("non-string inputs are rejected", function () {
  assert.throws(function () {
    analyzePassword(null);
  }, TypeError);
});

test("generator returns the requested length and includes every enabled character type", function () {
  const secureRandom = {
    getRandomValues: function (values) {
      values.fill(0);
      return values;
    }
  };
  const password = generatePassword(20, undefined, secureRandom);

  assert.equal(password.length, 20);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[0-9]/);
  assert.match(password, /[^A-Za-z0-9]/);
});

test("generator supports lengths through 30 and validates the length and character options", function () {
  const secureRandom = {
    getRandomValues: function (values) {
      values.fill(0);
      return values;
    }
  };

  assert.throws(function () {
    generatePassword(7, undefined, secureRandom);
  }, RangeError);
  assert.throws(function () {
    generatePassword(31, undefined, secureRandom);
  }, RangeError);
  assert.equal(generatePassword(30, undefined, secureRandom).length, 30);
  assert.throws(function () {
    generatePassword(12, {
      lowercase: false,
      uppercase: false,
      numbers: false,
      symbols: false
    }, secureRandom);
  }, RangeError);
});

test("generator supports selected types and excludes look-alike characters", function () {
  let nextRandomValue = 0;
  const secureRandom = {
    getRandomValues: function (values) {
      values.fill(nextRandomValue);
      nextRandomValue += 1;
      return values;
    }
  };
  const password = generatePassword(12, {
    lowercase: true,
    uppercase: false,
    numbers: false,
    symbols: false,
    avoidLookalikes: true
  }, secureRandom);

  assert.equal(password.length, 12);
  assert.match(password, /^[abcdefghijkmnopqrstuvwxyz]+$/);
});

test("generator rejects missing secure randomness", function () {
  assert.throws(function () {
    generatePassword(12, undefined, {});
  }, /Secure random generation is unavailable/);
});
