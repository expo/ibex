print(String(this));
print(typeof arguments);
try {
  accidentalGlobal = 1;
} catch (error) {
  print(error.name);
}
