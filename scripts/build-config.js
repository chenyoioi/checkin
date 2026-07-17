const fs = require("fs");

const FIELD_IDS = Object.freeze({
  max_speed: 1,
  acceleration: 2,
  cross_speed: 3,
  speed_factor_limit: 4,
  physics_scale_milli: 5,
});

function fail(message) {
  console.error(message);
  process.exit(1);
}

const inputPath = process.argv[2];
if (!inputPath) fail("Usage: node scripts/build-config.js <config.json>");

let input;
try {
  input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
} catch (error) {
  fail(`Cannot read config: ${error.message}`);
}

const entries = Object.entries(input).map(([name, value]) => {
  const id = FIELD_IDS[name];
  if (!id) fail(`Unknown config field: ${name}`);
  if (!Number.isSafeInteger(value) || value <= 0 || value > 0x7fffffff) {
    fail(`Invalid positive int32 value for ${name}`);
  }
  return { id, value };
}).sort((a, b) => a.id - b.id);

if (entries.length !== Object.keys(FIELD_IDS).length) {
  fail(`Config must contain: ${Object.keys(FIELD_IDS).join(", ")}`);
}

const output = Buffer.alloc(8 + entries.length * 6);
output.write("TCV2", 0, "ascii");
output.writeUInt16LE(2, 4);
output.writeUInt16LE(entries.length, 6);
entries.forEach((entry, index) => {
  const offset = 8 + index * 6;
  output.writeUInt16LE(entry.id, offset);
  output.writeInt32LE(entry.value, offset + 2);
});

process.stdout.write(output.toString("base64") + "\n");
