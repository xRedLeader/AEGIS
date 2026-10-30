function unsafeTypeScript(value: string) {
  return eval(value);
}
function safeTypeScript(value: string) {
  return JSON.parse(value);
}
