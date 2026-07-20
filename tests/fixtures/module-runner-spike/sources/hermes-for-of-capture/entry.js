const callbacks = [];
for (const item of ["a", "b"]) {
  callbacks.push(() => item);
}
export const joined = callbacks.map((callback) => callback()).join(",");
print(joined);
