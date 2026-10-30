function unsafeJavaScript(value) {
  return eval(value);
}
function safeJavaScript(value) {
  return JSON.parse(value);
}
